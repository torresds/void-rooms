use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::MAX_VAULT_SIZE;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    VaultTooLarge,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "vault storage operation failed",
            Self::VaultTooLarge => "vault exceeds the supported size",
        })
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn read_vault(path: impl AsRef<Path>) -> Result<Vec<u8>, StorageError> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > MAX_VAULT_SIZE as u64 {
        return Err(StorageError::VaultTooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_VAULT_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_VAULT_SIZE {
        return Err(StorageError::VaultTooLarge);
    }
    Ok(bytes)
}

pub fn write_vault_atomic(path: impl AsRef<Path>, vault_bytes: &[u8]) -> Result<(), StorageError> {
    write_vault_atomic_with(path.as_ref(), vault_bytes, || Ok(()))
}

fn write_vault_atomic_with(
    path: &Path,
    vault_bytes: &[u8],
    before_commit: impl FnOnce() -> io::Result<()>,
) -> Result<(), StorageError> {
    if vault_bytes.len() > MAX_VAULT_SIZE {
        return Err(StorageError::VaultTooLarge);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (temporary, mut file) = create_temporary_file(path)?;
    let result = (|| {
        file.write_all(vault_bytes)?;
        file.sync_all()?;
        before_commit()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(StorageError::Io)
}

fn temporary_path(path: &Path, sequence: u64) -> Result<PathBuf, StorageError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        StorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid vault path",
        ))
    })?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".tmp-{}-{sequence}", std::process::id()));
    Ok(parent.join(temporary_name))
}

fn create_temporary_file(path: &Path) -> Result<(PathBuf, File), StorageError> {
    create_temporary_file_from(path, TEMP_SEQUENCE.fetch_add(100, Ordering::Relaxed))
}

fn create_temporary_file_from(
    path: &Path,
    sequence_start: u64,
) -> Result<(PathBuf, File), StorageError> {
    for offset in 0..100 {
        let temporary = temporary_path(path, sequence_start + offset)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StorageError::Io(error)),
        }
    }
    Err(StorageError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary vault file",
    )))
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("void-vault-{unique}"));
        fs::create_dir_all(&directory).expect("create temp directory");
        directory.join("identity.vault")
    }

    #[test]
    fn atomic_write_round_trips_bytes() {
        let path = test_path();
        write_vault_atomic(&path, b"vault-data").expect("write vault");
        assert_eq!(read_vault(&path).expect("read vault"), b"vault-data");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn encrypted_identity_survives_process_restart() {
        const RESTART_PATH: &str = "VOID_CLIENT_CORE_RESTART_TEST_PATH";
        if let Some(path) = std::env::var_os(RESTART_PATH) {
            let stored = read_vault(path).expect("load persisted vault in child process");
            let restored = crate::DeviceIdentity::unlock(&stored, "local secret")
                .expect("restore identity in child process");
            assert_eq!(restored.identity(), b"native-device");
            assert_eq!(restored.signing_public_key().len(), 32);
            return;
        }

        let path = test_path();
        let identity = crate::DeviceIdentity::generate(b"native-device".to_vec(), "local secret")
            .expect("generate identity");
        let vault = identity.seal("local secret").expect("seal identity");
        write_vault_atomic(&path, &vault).expect("persist vault");
        drop(identity);

        let output = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("storage::tests::encrypted_identity_survives_process_restart")
            .env(RESTART_PATH, &path)
            .output()
            .expect("run restoration in a new process");
        assert!(output.status.success());
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn atomic_replacement_exposes_the_new_complete_record() {
        let path = test_path();
        write_vault_atomic(&path, b"old-record").expect("write initial vault");
        write_vault_atomic(&path, b"new-complete-record").expect("replace vault");
        assert_eq!(
            read_vault(&path).expect("read replaced vault"),
            b"new-complete-record"
        );
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn stale_temporary_files_do_not_block_vault_replacement() {
        let path = test_path();
        let next = 900_000 + TEMP_SEQUENCE.fetch_add(100, Ordering::Relaxed);
        let stale = path
            .parent()
            .expect("parent")
            .join(format!(".identity.vault.tmp-{}-{next}", std::process::id()));
        fs::write(&stale, b"interrupted write").expect("create stale temporary file");

        let (temporary, file) = create_temporary_file_from(&path, next)
            .expect("create replacement temp file after stale file");
        drop(file);
        assert_ne!(temporary, stale);
        fs::remove_file(temporary).expect("remove replacement temp file");
        write_vault_atomic(&path, b"new-record").expect("replace vault after restart");
        assert_eq!(read_vault(&path).expect("read vault"), b"new-record");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn failure_before_rename_preserves_previous_vault() {
        let path = test_path();
        write_vault_atomic(&path, b"old-record").expect("write initial vault");
        let result = write_vault_atomic_with(&path, b"new-record", || {
            Err(io::Error::other("injected interruption"))
        });
        assert!(result.is_err());
        assert_eq!(
            read_vault(&path).expect("read previous vault"),
            b"old-record"
        );
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }
}
