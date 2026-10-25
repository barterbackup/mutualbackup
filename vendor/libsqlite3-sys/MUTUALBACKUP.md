This is the crates.io `libsqlite3-sys` 0.35.0 package. `UPSTREAM.json` records the
original archive checksum and every original file's SHA-256. The original MIT
and SQLCipher licenses remain included. The workspace keeps the original
dependency versions and enabled SQLCipher/OpenSSL features.

The local changes are limited to `build.rs`, `src/lib.rs`, `sqlite3/sqlite3.c`
and `sqlcipher/sqlite3.c`. Bundled builds define the application file-control
opcode 1043 and the following Linux Unix-VFS interfaces. They install no global
syscall hook. Unsupported VFSes/platforms gain no new capability.

- `MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD` (1043) accepts an `int *` and returns
  the already open main, WAL, journal or temporary file descriptor.
- `MUTUALBACKUP_SQLITE_FCNTL_SHM_FD` (1044) accepts an `int *` and returns
  an already open SHM descriptor from the main file's attached SHM node. It
  returns SQLITE_NOTFOUND before attachment and in builds without WAL.

Both descriptor lookups return SQLITE_MISUSE for a null output argument and
SQLITE_NOTFOUND when the descriptor is unavailable. They perform no I/O,
allocation, descriptor open/close or lock change. Their results are borrowed:
keep the owning sqlite3_file alive, retain the mapped main-file connection for
SHM, avoid reentrant SQLite calls during use, and never close the descriptors
or change their locking/file-status flags.

`MUTUALBACKUP_SQLITE_FCNTL_SHM_INIT` (1045) registers a copied
`MutualBackupShmInit` callback/context pair on a main sqlite3_file before SHM
attachment. Null arguments, callbacks or contexts, or an already attached SHM
node, return SQLITE_MISUSE. The context and callback must remain valid through
native file close. When the first writable connection obtains the exclusive
native dead-man-switch (DMS) lock, SQLite truncates the stale SHM file to zero
and calls `init(context, descriptor, marker_size)`. The descriptor is borrowed
for that callback. Admission may allocate private extents and returns a SQLite
result code; success must set a marker size between 4096 and 65536 bytes. SQLite
then truncates to that size and downgrades DMS to a shared lock. Failure stops
SHM initialization. This reset and allocation therefore perform I/O under
native locks; the descriptor lookups' no-I/O guarantee does not apply here.
The callback must not reenter SQLite or independently open, close, truncate or
relock the native SHM file. The Rust adapter funds a complete filesystem block
before the marker extension, avoiding Btrfs inline conversion of a short marker.

`sqlite3_mutualbackup_open_temp_fd(vfs, file, descriptor)` transfers an anonymous
regular file into the built-in Unix VFS. Supply that native VFS and storage for
its sqlite3_file; the file must have zero links. Invalid arguments or a rejected
descriptor leave caller ownership unchanged. Upon acceptance, `*descriptor`
becomes -1 and native initialization/`xClose` owns cleanup, including an error
after acceptance. The caller must inspect the transferred descriptor value even
when the function returns an error, and must not close it twice. This interface
uses normal native temporary-file operations with `UNIXFILE_NOLOCK`; it avoids
reopening a procfs descriptor link or altering a main file's lock ownership.

The C implementation reads `unixFile.h` inside the same pinned translation
unit that defines it; Rust uses no private native-file layout. The standard
Unix methods, encryption, journals, SHM, filenames and directory ownership
continue through the original VFS.

These interfaces support native identity checks and the explicit runtime
physical VFS in `mb-store`. They do not themselves establish durable writer
enrollment, aggregate reservations, checkpoint/rebuild funding or a complete
physical resource policy.
