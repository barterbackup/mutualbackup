use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

pub(crate) struct PreservedScratchFixture(pub(crate) Option<tempfile::TempDir>);
impl Drop for PreservedScratchFixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let root = self.0.as_ref().unwrap().path();
            // Preserve live anonymous bytes before the connection closes.
            for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
                let fd = entry.path();
                let Ok(target) = std::fs::read_link(&fd) else {
                    continue;
                };
                if target.starts_with(root)
                    && target
                        .as_os_str()
                        .as_encoded_bytes()
                        .ends_with(b" (deleted)")
                {
                    let capture = || -> std::io::Result<()> {
                        let mut source = std::fs::File::open(&fd)?;
                        let mut copy = std::fs::File::create(
                            root.join(format!("raw-{}", entry.file_name().to_string_lossy())),
                        )?;
                        let mut buffer = [0; 65536];
                        loop {
                            let n = source.read(&mut buffer)?;
                            if n == 0 {
                                break;
                            }
                            copy.write_all(&buffer[..n])?;
                        }
                        copy.sync_all()?;
                        let m = source.metadata()?;
                        std::fs::write(
                            root.join(format!("metadata-{}", entry.file_name().to_string_lossy())),
                            format!("length={} blocks={}\n", m.len(), m.blocks()),
                        )
                    };
                    if let Err(error) = capture() {
                        eprintln!("scratch capture failed: {error}");
                    }
                }
            }
            eprintln!(
                "GIT_PREFLIGHT_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}
