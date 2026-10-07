//! Linux getdents64 cookies, independent of libc DIR stream lifetime. The
//! checkpoint owner must fence directory identity/change metadata before seek.
use super::*;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;

pub(super) struct DirectoryEntries {
    file: File,
    buffer: [u8; 8_192],
    position: usize,
    filled: usize,
    cookie: i64,
}

pub(super) struct Entry {
    pub name: OsString,
    pub may_be_directory: bool,
}

impl DirectoryEntries {
    pub fn new(directory: &PinnedDirectory) -> Result<Self, AnchorError> {
        // This duplicate shares only the directory enumeration offset. All
        // capability operations use openat2 and do not inspect that offset.
        Ok(Self {
            file: directory.as_file().try_clone()?,
            buffer: [0; 8_192],
            position: 0,
            filled: 0,
            cookie: 0,
        })
    }

    pub fn cookie(&self) -> i64 {
        self.cookie
    }

    pub fn seek(&mut self, cookie: i64) -> Result<(), AnchorError> {
        let offset = u64::try_from(cookie).map_err(|_| AnchorError::UnsafePath)?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.cookie = cookie;
        self.position = 0;
        self.filled = 0;
        Ok(())
    }

    pub fn next(&mut self) -> Result<Option<Entry>, AnchorError> {
        if self.position == self.filled {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    self.file.as_raw_fd(),
                    self.buffer.as_mut_ptr(),
                    self.buffer.len(),
                )
            };
            if count < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if count == 0 {
                return Ok(None);
            }
            self.filled = usize::try_from(count).map_err(|_| AnchorError::UnsafePath)?;
            if self.filled > self.buffer.len() {
                return Err(AnchorError::UnsafePath);
            }
            self.position = 0;
        }
        let bytes = &self.buffer[self.position..self.filled];
        if bytes.len() < 20 {
            return Err(AnchorError::UnsafePath);
        }
        let len = u16::from_ne_bytes(bytes[16..18].try_into().expect("fixed header")) as usize;
        if len < 20 || len > bytes.len() {
            return Err(AnchorError::UnsafePath);
        }
        let cookie = i64::from_ne_bytes(bytes[8..16].try_into().expect("fixed header"));
        if cookie < 0 {
            return Err(AnchorError::UnsafePath);
        }
        let name = &bytes[19..len];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(AnchorError::UnsafePath)?;
        if end == 0 || end > 255 || name[..end].contains(&b'/') {
            return Err(AnchorError::UnsafePath);
        }
        let entry = Entry {
            name: OsString::from_vec(name[..end].to_vec()),
            may_be_directory: matches!(bytes[18], libc::DT_DIR | libc::DT_UNKNOWN),
        };
        self.cookie = cookie;
        self.position += len;
        Ok(Some(entry))
    }
}
