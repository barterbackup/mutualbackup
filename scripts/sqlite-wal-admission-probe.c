/* Exercise the plain bundled SQLite WAL callback, independently of SQLCipher. */
#include "sqlite3.h"
#ifdef NDEBUG
#error "WAL admission probe requires active assertions"
#endif
#include <assert.h>
#include <stdio.h>

static sqlite3_vfs *native_vfs;
static const sqlite3_io_methods *native_methods;
static sqlite3_io_methods methods;
static sqlite3_int64 limit = 65536;
static sqlite3_int64 observed;
static int calls;
static sqlite3_file *peer_file;
static int unprotected;

static int admit(sqlite3_file *file, int op, void *argument) {
  if (op == 1046) {
    assert(argument != NULL);
    observed = *(sqlite3_int64 *)argument;
    assert(observed >= 0);
    ++calls;
    if (peer_file != NULL && observed > 0) {
      int rc = peer_file->pMethods->xShmLock(peer_file, 1, 1,
                                            SQLITE_SHM_LOCK | SQLITE_SHM_EXCLUSIVE);
      if (rc == SQLITE_OK) {
        ++unprotected;
        assert(peer_file->pMethods->xShmLock(peer_file, 1, 1,
                 SQLITE_SHM_UNLOCK | SQLITE_SHM_EXCLUSIVE) == SQLITE_OK);
      } else {
        assert(rc == SQLITE_BUSY);
      }
    }
    return observed > limit ? SQLITE_FULL : SQLITE_OK;
  }
  return native_methods->xFileControl(file, op, argument);
}

static int open_proxy(sqlite3_vfs *vfs, const char *name, sqlite3_file *file,
                      int flags, int *output) {
  (void)vfs;
  int rc = native_vfs->xOpen(native_vfs, name, file, flags, output);
  if (rc == SQLITE_OK && (flags & SQLITE_OPEN_MAIN_DB)) {
    native_methods = file->pMethods;
    methods = *native_methods;
    methods.xFileControl = admit;
    file->pMethods = &methods;
  }
  return rc;
}

static void execute(sqlite3 *db, const char *sql) {
  int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
  if (rc != SQLITE_OK) fprintf(stderr, "%s: %s\n", sql, sqlite3_errmsg(db));
  assert(rc == SQLITE_OK);
}

static sqlite3_int64 scalar(sqlite3 *db, const char *sql) {
  sqlite3_stmt *statement = NULL;
  assert(sqlite3_prepare_v2(db, sql, -1, &statement, NULL) == SQLITE_OK);
  assert(sqlite3_step(statement) == SQLITE_ROW);
  sqlite3_int64 value = sqlite3_column_int64(statement, 0);
  assert(sqlite3_finalize(statement) == SQLITE_OK);
  return value;
}

int main(void) {
  assert(sqlite3_initialize() == SQLITE_OK);
  native_vfs = sqlite3_vfs_find(NULL);
  assert(native_vfs != NULL);
  sqlite3_vfs proxy = *native_vfs;
  proxy.zName = "mutualbackup-wal-admission-probe";
  proxy.pNext = NULL;
  proxy.xOpen = open_proxy;
  assert(sqlite3_vfs_register(&proxy, 0) == SQLITE_OK);
  sqlite3 *db = NULL;
  assert(sqlite3_open_v2("admitted.db", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         proxy.zName) == SQLITE_OK);
  execute(db, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
              "CREATE TABLE records(value BLOB); INSERT INTO records VALUES ('original');");
  sqlite3 *peer = NULL;
  assert(sqlite3_open("admitted.db", &peer) == SQLITE_OK);
  assert(scalar(peer, "SELECT count(*) FROM records") == 1);
  assert(sqlite3_file_control(peer, "main", SQLITE_FCNTL_FILE_POINTER, &peer_file) == SQLITE_OK);
  int previous = calls;
  assert(sqlite3_exec(db, "BEGIN; INSERT INTO records VALUES (zeroblob(1048576)); COMMIT;",
                      NULL, NULL, NULL) == SQLITE_FULL);
  assert(calls > previous && observed > limit);
  if (!sqlite3_get_autocommit(db)) execute(db, "ROLLBACK");
  assert(scalar(db, "SELECT count(*) FROM records") == 1);
  assert(scalar(db, "SELECT value='original' FROM records") == 1);
  limit = 4 * 1024 * 1024;
  execute(db, "INSERT INTO records VALUES (zeroblob(1048576))");
  assert(scalar(db, "SELECT count(*) FROM records") == 2);
  assert(observed == scalar(db, "PRAGMA page_count") * scalar(db, "PRAGMA page_size"));
  assert(unprotected == 0);
  peer_file = NULL;
  assert(sqlite3_close(peer) == SQLITE_OK);
  assert(sqlite3_close(db) == SQLITE_OK);
  previous = calls;
  assert(sqlite3_open("unmanaged.db", &db) == SQLITE_OK);
  execute(db, "PRAGMA journal_mode=WAL; CREATE TABLE records(value BLOB);"
              "INSERT INTO records VALUES (zeroblob(1048576));");
  assert(scalar(db, "SELECT length(value) FROM records") == 1048576);
  assert(calls == previous);
  assert(sqlite3_close(db) == SQLITE_OK);
  assert(sqlite3_vfs_unregister(&proxy) == SQLITE_OK);
  printf("WAL admission: rollback, exact main size, retry and unmanaged commit pass (%d callbacks)\n", calls);
  return 0;
}
