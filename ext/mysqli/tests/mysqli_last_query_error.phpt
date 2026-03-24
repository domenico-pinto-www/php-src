--TEST--
mysqli last_query_error property stores the failed query string
--EXTENSIONS--
mysqli
--SKIPIF--
<?php
require_once 'skipifconnectfailure.inc';
?>
--FILE--
<?php
require_once 'connect.inc';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$mysqli = new mysqli($host, $user, $passwd, $db, $port, $socket);

try {
    $mysqli->query("SELECT * FROM non_existent_table_xyz");
} catch (mysqli_sql_exception $e) {
    echo $mysqli->last_query_error . "\n";
}

$mysqli->close();
?>
--EXPECT--
SELECT * FROM non_existent_table_xyz