#ifndef MYSQLI_CACHE_H
#define MYSQLI_CACHE_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "php.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_structs.h"

#define MYSQLI_CACHE_MAGIC        0xCAC4E00
#define MYSQLI_CACHE_ENTRY_MAGIC  0xCAC4E01
#define MYSQLI_CACHE_VERSION      1
#define MYSQLI_CACHE_KEY_LEN      33   /* MD5 hex + null */
#define MYSQLI_CACHE_MAX_SLOTS    1024 /* max cached queries */
#define MYSQLI_CACHE_DEFAULT_SIZE (16 * 1024 * 1024) /* 16 MB */
#define MYSQLI_CACHE_DEFAULT_TTL  30   /* seconds */
#define MYSQLI_CACHE_FILE         "/tmp/php_mysqli_cache"

/* Index slot in shared memory header */
typedef struct {
	char     key[MYSQLI_CACHE_KEY_LEN]; /* MD5 of query */
	uint64_t offset;                    /* offset of data in mmap file */
	uint32_t data_size;                 /* bytes of serialized data */
	int64_t  created_at;                /* unix timestamp */
	uint32_t ttl;                       /* seconds */
	uint8_t  in_use;                    /* 1 = occupied */
} mysqli_cache_slot_t;

/* Shared memory header (at offset 0 of mmap file) */
typedef struct {
	uint32_t           magic;
	uint32_t           version;
	uint64_t           max_size;        /* total mmap file size */
	uint64_t           data_offset;     /* current write position for data */
	uint32_t           num_entries;
	pthread_mutex_t    lock;
	mysqli_cache_slot_t slots[MYSQLI_CACHE_MAX_SLOTS];
} mysqli_cache_header_t;

#define MYSQLI_CACHE_HEADER_SIZE  sizeof(mysqli_cache_header_t)

/* Functions */
int  mysqli_cache_init(size_t max_bytes, const char *filepath);
void mysqli_cache_shutdown(void);
void mysqli_cache_compute_key(const char *query, size_t query_len, char out_key[MYSQLI_CACHE_KEY_LEN]);
bool mysqli_cache_is_blacklisted(const char *query, size_t query_len);
bool mysqli_cache_lookup(const char *key, uint32_t ttl, void **out_data, uint32_t *out_size);
bool mysqli_cache_store(const char *key, uint32_t ttl, const void *data, uint32_t data_size);
void mysqli_cache_log(const char *level, const char *key, const char *query, const char *extra);

/* Result serialization */
void *mysqli_cache_serialize_result(MYSQLND_RES *result, uint32_t *out_size);
MYSQLND_RES *mysqli_cache_deserialize_result(MYSQLND_CONN_DATA *conn, const void *data, uint32_t data_size);

#endif /* MYSQLI_CACHE_H */