#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <syslog.h>

#include "php.h"
#include "ext/standard/md5.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_result.h"
#include "ext/mysqlnd/mysqlnd_result_meta.h"
#include "ext/mysqlnd/mysqlnd_block_alloc.h"
#include "ext/mysqlnd/mysqlnd_alloc.h"
#include "mysqli_cache.h"
#include "php_mysqli_structs.h"

/* Global pointer to shared memory header */
static mysqli_cache_header_t *cache_shm = NULL;
static size_t cache_shm_size = 0;
static char cache_file_path[256] = MYSQLI_CACHE_FILE;

/* -------------------------------------------------------------------------
 * Init / Shutdown
 * ---------------------------------------------------------------------- */

int mysqli_cache_init(size_t max_bytes, const char *filepath)
{
	if (filepath && filepath[0]) {
		strlcpy(cache_file_path, filepath, sizeof(cache_file_path));
	}

	int fd = open(cache_file_path, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		return FAILURE;
	}

	struct stat st;
	bool is_new = (fstat(fd, &st) == 0 && st.st_size < (off_t)max_bytes);
	if (is_new) {
		if (ftruncate(fd, max_bytes) < 0) {
			close(fd);
			return FAILURE;
		}
	}

	cache_shm = (mysqli_cache_header_t *)mmap(
		NULL, max_bytes,
		PROT_READ | PROT_WRITE,
		MAP_SHARED, fd, 0
	);
	close(fd);

	if (cache_shm == MAP_FAILED) {
		cache_shm = NULL;
		return FAILURE;
	}

	cache_shm_size = max_bytes;

	/* Initialize header if new or magic mismatch */
	if (cache_shm->magic != MYSQLI_CACHE_MAGIC) {
		memset(cache_shm, 0, sizeof(mysqli_cache_header_t));
		cache_shm->magic       = MYSQLI_CACHE_MAGIC;
		cache_shm->version     = MYSQLI_CACHE_VERSION;
		cache_shm->max_size    = max_bytes;
		cache_shm->data_offset = MYSQLI_CACHE_HEADER_SIZE;
		cache_shm->num_entries = 0;

		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&cache_shm->lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}

	return SUCCESS;
}

void mysqli_cache_shutdown(void)
{
	if (cache_shm && cache_shm != MAP_FAILED) {
		munmap(cache_shm, cache_shm_size);
		cache_shm = NULL;
	}
}

/* -------------------------------------------------------------------------
 * MD5 key computation
 * ---------------------------------------------------------------------- */

void mysqli_cache_compute_key(const char *query, size_t query_len, char out_key[MYSQLI_CACHE_KEY_LEN])
{
	PHP_MD5_CTX ctx;
	unsigned char digest[16];

	PHP_MD5Init(&ctx);
	PHP_MD5Update(&ctx, (const unsigned char *)query, query_len);
	PHP_MD5Final(digest, &ctx);
	make_digest(out_key, digest);
}

/* -------------------------------------------------------------------------
 * Blacklist check (time-dependent / non-deterministic functions)
 * ---------------------------------------------------------------------- */

static const char *blacklist_tokens[] = {
	"NOW(", "DATE(", "CURDATE(", "CURTIME(",
	"SYSDATE(", "UNIX_TIMESTAMP(", "RAND(", "UUID(",
	NULL
};

bool mysqli_cache_is_blacklisted(const char *query, size_t query_len)
{
	char *upper = emalloc(query_len + 1);
	for (size_t i = 0; i < query_len; i++) {
		upper[i] = toupper((unsigned char)query[i]);
	}
	upper[query_len] = '\0';

	bool found = false;
	for (int i = 0; blacklist_tokens[i] != NULL; i++) {
		if (strstr(upper, blacklist_tokens[i]) != NULL) {
			found = true;
			break;
		}
	}

	efree(upper);
	return found;
}

/* -------------------------------------------------------------------------
 * Cache lookup
 * ---------------------------------------------------------------------- */

bool mysqli_cache_lookup(const char *key, uint32_t ttl, void **out_data, uint32_t *out_size)
{
	if (!cache_shm) {
		return false;
	}

	pthread_mutex_lock(&cache_shm->lock);

	time_t now = time(NULL);
	bool found = false;

	for (uint32_t i = 0; i < MYSQLI_CACHE_MAX_SLOTS; i++) {
		mysqli_cache_slot_t *slot = &cache_shm->slots[i];

		if (!slot->in_use) {
			continue;
		}
		if (strncmp(slot->key, key, MYSQLI_CACHE_KEY_LEN) != 0) {
			continue;
		}

		uint32_t effective_ttl = (ttl > 0) ? ttl : slot->ttl;
		if ((now - slot->created_at) > effective_ttl) {
			slot->in_use = 0;
			cache_shm->num_entries--;
			break;
		}

		uint8_t *base = (uint8_t *)cache_shm;
		*out_data = emalloc(slot->data_size);
		memcpy(*out_data, base + slot->offset, slot->data_size);
		*out_size = slot->data_size;
		found = true;
		break;
	}

	pthread_mutex_unlock(&cache_shm->lock);
	return found;
}

/* -------------------------------------------------------------------------
 * Cache store
 * ---------------------------------------------------------------------- */

bool mysqli_cache_store(const char *key, uint32_t ttl, const void *data, uint32_t data_size)
{
	if (!cache_shm) {
		return false;
	}

	pthread_mutex_lock(&cache_shm->lock);

	time_t now = time(NULL);

	int free_slot = -1;
	int oldest_slot = -1;
	int64_t oldest_time = INT64_MAX;

	for (int i = 0; i < MYSQLI_CACHE_MAX_SLOTS; i++) {
		mysqli_cache_slot_t *slot = &cache_shm->slots[i];

		if (!slot->in_use) {
			free_slot = i;
			break;
		}
		if (strncmp(slot->key, key, MYSQLI_CACHE_KEY_LEN) == 0) {
			free_slot = i;
			cache_shm->num_entries--;
			break;
		}
		if ((now - slot->created_at) > slot->ttl) {
			free_slot = i;
			cache_shm->num_entries--;
			break;
		}
		if (slot->created_at < oldest_time) {
			oldest_time = slot->created_at;
			oldest_slot = i;
		}
	}

	if (free_slot < 0 && oldest_slot >= 0) {
		free_slot = oldest_slot;
		cache_shm->num_entries--;
	}

	if (free_slot < 0) {
		pthread_mutex_unlock(&cache_shm->lock);
		return false;
	}

	uint64_t needed_offset = cache_shm->data_offset + data_size;
	if (needed_offset > cache_shm->max_size) {
		cache_shm->data_offset = MYSQLI_CACHE_HEADER_SIZE;
		for (int i = 0; i < MYSQLI_CACHE_MAX_SLOTS; i++) {
			cache_shm->slots[i].in_use = 0;
		}
		cache_shm->num_entries = 0;
		free_slot = 0;

		if (MYSQLI_CACHE_HEADER_SIZE + data_size > cache_shm->max_size) {
			pthread_mutex_unlock(&cache_shm->lock);
			return false;
		}
	}

	uint8_t *base = (uint8_t *)cache_shm;
	memcpy(base + cache_shm->data_offset, data, data_size);

	mysqli_cache_slot_t *slot = &cache_shm->slots[free_slot];
	memcpy(slot->key, key, MYSQLI_CACHE_KEY_LEN);
	slot->offset     = cache_shm->data_offset;
	slot->data_size  = data_size;
	slot->created_at = now;
	slot->ttl        = ttl;
	slot->in_use     = 1;

	cache_shm->data_offset += data_size;
	cache_shm->num_entries++;

	pthread_mutex_unlock(&cache_shm->lock);
	return true;
}

/* -------------------------------------------------------------------------
 * Syslog helper
 * ---------------------------------------------------------------------- */

void mysqli_cache_log(const char *level, const char *key, const char *query, const char *extra)
{
	openlog("php-mysqli-cache", LOG_PID | LOG_NDELAY, LOG_USER);
	syslog(LOG_WARNING, "[%s] key=%s query=\"%.80s\" %s",
		level,
		key   ? key   : "-",
		query ? query : "-",
		extra ? extra : "");
	closelog();
}

/* -------------------------------------------------------------------------
 * Binary read/write helpers
 * ---------------------------------------------------------------------- */

#define WRITE_UINT8(buf, val)  do { *(uint8_t *)(buf) = (uint8_t)(val);  (buf) += 1; } while(0)
#define WRITE_UINT16(buf, val) do { uint16_t _v = (uint16_t)(val); memcpy((buf), &_v, 2); (buf) += 2; } while(0)
#define WRITE_UINT32(buf, val) do { uint32_t _v = (uint32_t)(val); memcpy((buf), &_v, 4); (buf) += 4; } while(0)
#define WRITE_UINT64(buf, val) do { uint64_t _v = (uint64_t)(val); memcpy((buf), &_v, 8); (buf) += 8; } while(0)
#define WRITE_BYTES(buf, src, len) do { if ((len) > 0) memcpy((buf), (src), (len)); (buf) += (len); } while(0)

#define READ_UINT8(buf, var)  do { (var) = *(uint8_t *)(buf);  (buf) += 1; } while(0)
#define READ_UINT16(buf, var) do { uint16_t _v; memcpy(&_v, (buf), 2); (var) = _v; (buf) += 2; } while(0)
#define READ_UINT32(buf, var) do { uint32_t _v; memcpy(&_v, (buf), 4); (var) = _v; (buf) += 4; } while(0)
#define READ_UINT64(buf, var) do { uint64_t _v; memcpy(&_v, (buf), 8); (var) = _v; (buf) += 8; } while(0)

static inline void write_str16(uint8_t **buf, const char *str, uint16_t len)
{
	WRITE_UINT16(*buf, len);
	if (len > 0 && str) {
		WRITE_BYTES(*buf, str, len);
	}
}

/* -------------------------------------------------------------------------
 * Result serialization
 *
 * Format:
 *   [magic: u32][nfields: u32][nrows: u64]
 *   For each field:
 *     [name_len u16][name]
 *     [org_name_len u16][org_name]
 *     [table_len u16][table]
 *     [org_table_len u16][org_table]
 *     [db_len u16][db]
 *     [type u32][flags u32][decimals u16][length u32][charsetnr u32]
 *     [is_numeric u8]
 *   For each row:
 *     [wire_size u32][wire_data: raw MySQL text protocol bytes]
 * ---------------------------------------------------------------------- */

void *mysqli_cache_serialize_result(MYSQLND_RES *res, uint32_t *out_size)
{
	if (!res || !res->stored_data) {
		return NULL;
	}

	unsigned int nfields = res->field_count;
	uint64_t nrows = res->stored_data->row_count;
	MYSQLND_FIELD *fields = res->meta->fields;

	/* First pass: compute needed buffer size */
	size_t total = 4 + 4 + 8; /* magic + nfields + nrows */

	for (unsigned int f = 0; f < nfields; f++) {
		MYSQLND_FIELD *field = &fields[f];
		total += 2 + field->name_length;
		total += 2 + field->org_name_length;
		total += 2 + field->table_length;
		total += 2 + field->org_table_length;
		total += 2 + field->db_length;
		total += 4 + 4 + 2 + 4 + 4 + 1; /* type, flags, decimals, length, charsetnr, is_numeric */
	}

	for (uint64_t r = 0; r < nrows; r++) {
		total += 4 + res->stored_data->row_buffers[r].size; /* wire_size + wire_data */
	}

	uint8_t *buf = emalloc(total);
	if (!buf) {
		return NULL;
	}
	uint8_t *ptr = buf;

	/* Write header */
	WRITE_UINT32(ptr, MYSQLI_CACHE_ENTRY_MAGIC);
	WRITE_UINT32(ptr, nfields);
	WRITE_UINT64(ptr, nrows);

	/* Write field metadata */
	for (unsigned int f = 0; f < nfields; f++) {
		MYSQLND_FIELD *field = &fields[f];
		write_str16(&ptr, field->name,      (uint16_t)field->name_length);
		write_str16(&ptr, field->org_name,  (uint16_t)field->org_name_length);
		write_str16(&ptr, field->table,     (uint16_t)field->table_length);
		write_str16(&ptr, field->org_table, (uint16_t)field->org_table_length);
		write_str16(&ptr, field->db,        (uint16_t)field->db_length);
		WRITE_UINT32(ptr, field->type);
		WRITE_UINT32(ptr, field->flags);
		WRITE_UINT16(ptr, field->decimals);
		WRITE_UINT32(ptr, field->length);
		WRITE_UINT32(ptr, field->charsetnr);
		WRITE_UINT8(ptr,  field->is_numeric ? 1 : 0);
	}

	/* Write raw wire-protocol row buffers (already in MySQL text format) */
	for (uint64_t r = 0; r < nrows; r++) {
		uint32_t ws = (uint32_t)res->stored_data->row_buffers[r].size;
		WRITE_UINT32(ptr, ws);
		WRITE_BYTES(ptr, res->stored_data->row_buffers[r].ptr, ws);
	}

	*out_size = (uint32_t)(ptr - buf);
	return buf;
}

/* -------------------------------------------------------------------------
 * Result deserialization
 * Reconstructs a proper MYSQLND_RES from the cached binary blob.
 * ---------------------------------------------------------------------- */

MYSQLND_RES *mysqli_cache_deserialize_result(MYSQLND_CONN_DATA *conn, const void *data, uint32_t data_size)
{
	(void)data_size;
	const uint8_t *ptr = (const uint8_t *)data;

	uint32_t magic, nfields;
	uint64_t nrows;

	READ_UINT32(ptr, magic);
	if (magic != MYSQLI_CACHE_ENTRY_MAGIC) {
		return NULL;
	}
	READ_UINT32(ptr, nfields);
	READ_UINT64(ptr, nrows);

	/* Create the result shell */
	MYSQLND_RES *res = mysqlnd_result_init(nfields);
	if (!res) {
		return NULL;
	}

	MYSQLND_MEMORY_POOL *pool = res->memory_pool;

	/* Create and populate field metadata (all pool-allocated) */
	res->meta = mysqlnd_result_meta_init(res, nfields);
	if (!res->meta) {
		mysqlnd_free_result(res, false);
		return NULL;
	}

	MYSQLND_FIELD *fields = res->meta->fields;

	for (unsigned int f = 0; f < nfields; f++) {
		MYSQLND_FIELD *field = &fields[f];
		uint16_t len;

		/* Read each string length then copy into pool-allocated root buffer.
		 * We build a single root buffer: name\0 org_name\0 table\0 org_table\0 db\0 */
		uint16_t name_len, org_name_len, table_len, org_table_len, db_len;
		const uint8_t *name_p, *org_name_p, *table_p, *org_table_p, *db_p;

		READ_UINT16(ptr, name_len);      name_p      = ptr; ptr += name_len;
		READ_UINT16(ptr, org_name_len);  org_name_p  = ptr; ptr += org_name_len;
		READ_UINT16(ptr, table_len);     table_p     = ptr; ptr += table_len;
		READ_UINT16(ptr, org_table_len); org_table_p = ptr; ptr += org_table_len;
		READ_UINT16(ptr, db_len);        db_p        = ptr; ptr += db_len;

		/* Allocate a single root buffer for all strings of this field */
		size_t root_size = (size_t)name_len + 1 + org_name_len + 1
		                 + table_len + 1 + org_table_len + 1 + db_len + 1;
		char *root = pool->get_chunk(pool, root_size);
		char *wp = root;

		#define COPY_FIELD_STR(dst, src, slen) do { \
			memcpy(wp, (src), (slen)); wp[(slen)] = '\0'; \
			(dst) = wp; wp += (slen) + 1; \
		} while(0)

		COPY_FIELD_STR(field->name,      name_p,      name_len);
		COPY_FIELD_STR(field->org_name,  org_name_p,  org_name_len);
		COPY_FIELD_STR(field->table,     table_p,     table_len);
		COPY_FIELD_STR(field->org_table, org_table_p, org_table_len);
		COPY_FIELD_STR(field->db,        db_p,        db_len);

		#undef COPY_FIELD_STR

		field->name_length      = name_len;
		field->org_name_length  = org_name_len;
		field->table_length     = table_len;
		field->org_table_length = org_table_len;
		field->db_length        = db_len;
		field->root             = root;
		field->root_len         = root_size;

		/* sname: explicit zend_string (freed explicitly on metadata free) */
		field->sname = zend_string_init(field->name, name_len, 0);
		(void)len; /* suppress unused warning */

		uint32_t type, flags, length, charsetnr;
		uint16_t decimals;
		uint8_t is_numeric;
		READ_UINT32(ptr, type);
		READ_UINT32(ptr, flags);
		READ_UINT16(ptr, decimals);
		READ_UINT32(ptr, length);
		READ_UINT32(ptr, charsetnr);
		READ_UINT8(ptr,  is_numeric);

		field->type       = (enum mysqlnd_field_types)type;
		field->flags      = flags;
		field->decimals   = decimals;
		field->length     = length;
		field->charsetnr  = charsetnr;
		field->is_numeric = (bool)is_numeric;
	}

	/* Create stored_data (buffered, text protocol since stmt=NULL) */
	res->stored_data = mysqlnd_result_buffered_init(res, nfields, NULL);
	if (!res->stored_data) {
		mysqlnd_free_result(res, false);
		return NULL;
	}

	/* Allocate row_buffers array (NOT pool - freed with mnd_efree) */
	if (nrows > 0) {
		res->stored_data->row_buffers = mnd_emalloc(nrows * sizeof(MYSQLND_ROW_BUFFER));
		if (!res->stored_data->row_buffers) {
			mysqlnd_free_result(res, false);
			return NULL;
		}
	}
	res->stored_data->row_count   = nrows;
	res->stored_data->current_row = 0;

	/* Restore raw wire-protocol buffers from cache into the pool */
	MYSQLND_MEMORY_POOL *row_pool = res->stored_data->result_set_memory_pool;
	for (uint64_t r = 0; r < nrows; r++) {
		uint32_t ws;
		READ_UINT32(ptr, ws);

		void *row_buf = row_pool->get_chunk(row_pool, ws);
		memcpy(row_buf, ptr, ws);
		ptr += ws;

		res->stored_data->row_buffers[r].ptr  = row_buf;
		res->stored_data->row_buffers[r].size = ws;
	}

	res->type  = MYSQLND_RES_NORMAL;
	res->unbuf = NULL;

	/* Increment refcount so free_result doesn't destroy the connection */
	conn->m->get_reference(conn);
	res->conn = conn;

	res->row_data = pool->get_chunk(pool, nfields * sizeof(zval));
	memset(res->row_data, 0, nfields * sizeof(zval));
	res->free_row_data = 0; /* pool-allocated, freed with pool */

	return res;
}