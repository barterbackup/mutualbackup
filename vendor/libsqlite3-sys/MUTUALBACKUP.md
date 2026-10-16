This is the crates.io `libsqlite3-sys` 0.35.0 package. `UPSTREAM.json` records the
original archive checksum and every original file's SHA-256. The original MIT
and SQLCipher licenses remain included. The workspace keeps the original
dependency versions and enabled SQLCipher/OpenSSL features.

The local changes are limited to `build.rs`, `src/lib.rs`, `sqlite3/sqlite3.c`
and `sqlcipher/sqlite3.c`. Bundled builds define the application file-control
opcode 1043, exported as `MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD`. On Linux the
native Unix VFS accepts an `int *` and returns its already open descriptor.
A null argument returns SQLITE_MISUSE; an unavailable descriptor or unsupported
VFS returns SQLITE_NOTFOUND. The caller must keep the sqlite3_file alive, avoid
reentrant SQLite calls during use, and never close the descriptor or change
locking/file-status flags. The extension performs no I/O, allocation, descriptor
open/close, or lock change. It installs no global syscall hook.

The C implementation reads `unixFile.h` inside the same pinned translation
unit that defines it; Rust uses no private native-file layout. The standard
Unix methods, encryption, journals, SHM, filenames and directory ownership
continue through the original VFS. Other platforms gain no new capability.

This descriptor bridge supports native identity checks and future extent
admission. It does not reserve SQL/WAL blocks, establish private CoW extents,
fund checkpoints or qualify a complete physical resource policy.
