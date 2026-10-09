//! Linux mount coordinates for available preserved path hints. A bind mount of
//! a descendant need not expose the original root in its pathname ancestry.

use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

// Match the existing native anchor discovery mount-info read bound. This is
// placement metadata, separate from still-open enclosing catalog budgets.
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug)]
struct Mount {
    device: (u32, u32),
    btrfs: bool,
    root: PathBuf,
    point: PathBuf,
}

#[derive(Debug)]
pub(super) struct MountTable {
    hash: blake3::Hash,
    mounts: Vec<Mount>,
}

#[derive(Debug)]
pub(super) struct Coordinate {
    device: (u32, u32),
    path: PathBuf,
}

impl Coordinate {
    pub(super) fn is_within(&self, other: &Self) -> bool {
        self.device == other.device && self.path.starts_with(&other.path)
    }
}

impl MountTable {
    pub(super) fn read() -> Result<Self> {
        Self::parse(&read_mountinfo()?)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_MOUNTINFO_BYTES,
            "cannot verify placement mount table within its metadata bound"
        );
        let mut mounts = Vec::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
            ensure!(
                fields.len() >= 10,
                "cannot verify malformed placement mount table"
            );
            let separator = fields[6..]
                .iter()
                .position(|field| *field == b"-")
                .map(|position| position + 6)
                .context("placement mount separator is missing")?;
            ensure!(
                separator + 3 < fields.len(),
                "placement mount filesystem fields are missing"
            );
            let device = std::str::from_utf8(fields[2])?
                .split_once(':')
                .context("invalid placement mount device")?;
            mounts.push(Mount {
                device: (device.0.parse()?, device.1.parse()?),
                btrfs: fields[separator + 1] == b"btrfs",
                root: decode_path(fields[3])?,
                point: decode_path(fields[4])?,
            });
        }
        ensure!(!mounts.is_empty(), "placement mount table is empty");
        Ok(Self {
            hash: blake3::hash(bytes),
            mounts,
        })
    }

    pub(super) fn coordinate(&self, path: &Path) -> Result<Coordinate> {
        let metadata = path.metadata()?;
        self.coordinate_on(
            path,
            (libc::major(metadata.dev()), libc::minor(metadata.dev())),
        )
    }

    fn coordinate_on(&self, path: &Path, device: (u32, u32)) -> Result<Coordinate> {
        ensure!(path.is_absolute(), "placement path is not absolute");
        let longest = self
            .mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.point))
            .map(|mount| mount.point.as_os_str().len())
            .max()
            .context("placement path has no visible mount")?;
        let mut matches = self.mounts.iter().filter(|mount| {
            mount.point.as_os_str().len() == longest && path.starts_with(&mount.point)
        });
        let mount = matches.next().context("placement mount disappeared")?;
        // Hidden stacked mounts require a mount-ID proof. Refuse ambiguity
        // rather than choosing the first or last row in mountinfo.
        ensure!(matches.next().is_none(), "placement mount is ambiguous");
        // Btrfs st_dev is an anonymous device for the current subvolume. It
        // differs even at the top-level root from mountinfo's superblock
        // device. The latter plus the full filesystem root path identifies
        // bind aliases across subvolumes; it is never a NativeFileId.
        ensure!(
            mount.btrfs || mount.device == device,
            "placement mount device changed"
        );
        Ok(Coordinate {
            device: mount.device,
            path: mount.root.join(path.strip_prefix(&mount.point)?),
        })
    }

    pub(super) fn require_unchanged(&self) -> Result<()> {
        ensure!(
            blake3::hash(&read_mountinfo()?) == self.hash,
            "placement mount table changed during preflight; retry with a stable destination"
        );
        Ok(())
    }
}

fn read_mountinfo() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_MOUNTINFO_BYTES,
        "placement mount table exceeds its metadata bound"
    );
    Ok(bytes)
}

fn decode_path(bytes: &[u8]) -> Result<PathBuf> {
    ensure!(
        bytes.len() <= MAX_PATH_BYTES * 4,
        "placement mount path is too long"
    );
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'\\' {
            let escape = bytes
                .get(index + 1..index + 4)
                .context("truncated mount path escape")?;
            index += 3;
            match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => anyhow::bail!("invalid mount path escape"),
            }
        } else {
            bytes[index]
        };
        ensure!(byte != 0, "mount path contains NUL");
        decoded.push(byte);
        ensure!(
            decoded.len() <= MAX_PATH_BYTES,
            "placement mount path is too long"
        );
        index += 1;
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    ensure!(path.is_absolute(), "mount path is not absolute");
    let mut normalized = PathBuf::new();
    for component in path.components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "mount path is not normalized"
        );
        normalized.push(component.as_os_str());
    }
    ensure!(
        normalized.as_os_str() == path.as_os_str(),
        "mount path is not canonical"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn legacy_placement_mount_coordinates_exclude_descendants_across_bind_aliases() {
        let table = MountTable::parse(
            b"1 0 8:1 / / rw - ext4 /dev/root rw\n\
              2 1 8:1 /protected/child /alias rw shared:1 - ext4 /dev/root rw\n\
              3 1 8:1 /protected/child/deep /nested rw - ext4 /dev/root rw\n\
              4 1 8:2 /protected/child /foreign rw - ext4 /dev/other rw\n\
              5 1 8:1 /tree1 /subvol1 rw - btrfs /dev/root rw\n\
              6 1 8:1 /tree2 /subvol2 rw - btrfs /dev/root rw\n",
        )
        .unwrap();
        let owner = table
            .coordinate_on(Path::new("/protected"), (8, 1))
            .unwrap();
        for (path, device, inside) in [
            ("/protected", (8, 1), true),
            ("/alias/recovery", (8, 1), true),
            ("/nested/recovery", (8, 1), true),
            ("/foreign/recovery", (8, 2), false),
            ("/protected-other", (8, 1), false),
            ("/alias-other", (8, 1), false),
            ("/safe", (8, 1), false),
        ] {
            assert_eq!(
                table
                    .coordinate_on(Path::new(path), device)
                    .unwrap()
                    .is_within(&owner),
                inside,
                "{path}"
            );
        }
        let subvolume = table.coordinate_on(Path::new("/subvol1"), (8, 1)).unwrap();
        assert!(
            !table
                .coordinate_on(Path::new("/subvol2/child"), (8, 1))
                .unwrap()
                .is_within(&subvolume)
        );
        assert!(table.coordinate_on(Path::new("/alias"), (8, 2)).is_err());
        assert!(table.coordinate_on(Path::new("relative"), (8, 1)).is_err());
        let btrfs = MountTable::parse(b"1 0 0:45 / /volume rw - btrfs /dev/loop rw\n2 1 0:45 /subvolume/child /alias rw - btrfs /dev/loop rw\n3 1 0:45 /another/child /other rw - btrfs /dev/loop rw\n").unwrap();
        let owner = btrfs
            .coordinate_on(Path::new("/volume/subvolume"), (0, 47))
            .unwrap();
        assert!(
            btrfs
                .coordinate_on(Path::new("/alias/recovery"), (0, 47))
                .unwrap()
                .is_within(&owner)
        );
        assert!(
            !btrfs
                .coordinate_on(Path::new("/other/recovery"), (0, 48))
                .unwrap()
                .is_within(&owner)
        );
    }

    #[test]
    fn legacy_placement_mount_parser_preserves_raw_paths_and_rejects_ambiguous_or_oversized_tables()
    {
        let path = decode_path(b"/a\\040b\\011c\\012d\\134e\xff").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/a b\tc\nd\\e\xff");
        let mut boundary = vec![b'x'; MAX_PATH_BYTES];
        boundary[0] = b'/';
        assert!(decode_path(&boundary).is_ok());
        boundary.push(b'x');
        assert!(decode_path(&boundary).is_err());
        for path in [
            b"relative".as_slice(),
            b"/a/../b",
            b"/a/./b",
            b"//a",
            b"/a\\",
            b"/a\\000",
            b"/a\\041",
            b"/a\0b",
        ] {
            assert!(decode_path(path).is_err(), "{path:?}");
        }
        for bytes in [
            b"".as_slice(),
            b"1 0 bad / / rw - ext4 source rw\n",
            b"1 0 8:1 / / rw ext4 source rw\n",
            b"1 0 8:1 relative / rw - ext4 source rw\n",
        ] {
            assert!(MountTable::parse(bytes).is_err(), "{bytes:?}");
        }
        let ambiguous = MountTable::parse(b"1 0 8:1 / / rw - ext4 source rw\n2 1 8:1 /first /stack rw - ext4 source rw\n3 2 8:1 /second /stack rw - ext4 source rw\n").unwrap();
        assert!(
            ambiguous
                .coordinate_on(Path::new("/stack/child"), (8, 1))
                .is_err()
        );
        let mut maximum = b"1 0 8:1 / / rw - ext4 source ".to_vec();
        maximum.resize(MAX_MOUNTINFO_BYTES - 1, b'x');
        maximum.push(b'\n');
        assert!(MountTable::parse(&maximum).is_ok());
        maximum.push(b'\n');
        assert!(MountTable::parse(&maximum).is_err());
    }
}
