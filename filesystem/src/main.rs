use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

use rust_ffi::key_management::{protect_keypair_file, unprotect_keypair_file};
use rust_ffi::recipient_encryption::{decrypt_for_recipient, encrypt_for_recipient};
use rust_ffi::safe::{MlKem768KeyPair, mlkem768_keypair};

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INODE: INodeNo = INodeNo::ROOT;

struct FileEntry {
    inode: INodeNo,
    content: Vec<u8>,
    permissions: u16,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
}

struct FileSystemState {
    files: HashMap<String, FileEntry>,
    next_inode: u64,
}

struct QuantumVaultFS {
    state: Mutex<FileSystemState>,
    keypair: MlKem768KeyPair,
    storage_dir: PathBuf,
}

impl QuantumVaultFS {
    fn new(keypair: MlKem768KeyPair, storage_dir: PathBuf) -> io::Result<Self> {
        let mut files = HashMap::new();
        let mut next_inode = 2u64;

        for entry in fs::read_dir(&storage_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) != Some("qv") {
                continue;
            }

            let Some(encoded_name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let name_bytes = match decode_hex(encoded_name) {
                Some(bytes) => bytes,
                None => {
                    eprintln!("Skipping invalid encrypted filename: {:?}", path);
                    continue;
                }
            };

            let name = String::from_utf8(name_bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Encrypted filename is not valid UTF-8",
                )
            })?;

            if !valid_filename(&name) {
                continue;
            }

            let encrypted_content = fs::read(&path)?;

            let content = decrypt_for_recipient(&encrypted_content, &keypair).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unable to decrypt stored file {:?}: {:?}", name, error),
                )
            })?;

            let now = SystemTime::now();
            let inode = INodeNo(next_inode);
            next_inode += 1;

            files.insert(
                name,
                FileEntry {
                    inode,
                    content,
                    permissions: 0o600,
                    atime: now,
                    mtime: now,
                    ctime: now,
                },
            );
        }

        println!("Loaded {} encrypted file(s).", files.len());

        Ok(Self {
            state: Mutex::new(FileSystemState { files, next_inode }),
            keypair,
            storage_dir,
        })
    }

    fn persist_file(&self, name: &str, content: &[u8]) -> io::Result<()> {
        let encrypted =
            encrypt_for_recipient(content, &self.keypair.public_key).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Encryption failed: {:?}", error),
                )
            })?;

        let encoded_name = encode_hex(name.as_bytes());
        let final_path = self.storage_dir.join(format!("{}.qv", encoded_name));

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let temp_path = self.storage_dir.join(format!(
            ".{}.{}.{}.tmp",
            encoded_name,
            std::process::id(),
            timestamp
        ));

        let write_result = (|| -> io::Result<()> {
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;

            temp_file.write_all(&encrypted)?;
            temp_file.sync_all()?;

            fs::rename(&temp_path, &final_path)?;

            // Best-effort directory synchronization after atomic rename.
            if let Ok(directory) = File::open(&self.storage_dir) {
                let _ = directory.sync_all();
            }

            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }

        write_result
    }
}

impl Filesystem for QuantumVaultFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent != ROOT_INODE {
            reply.error(Errno::ENOENT);
            return;
        }

        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };

        let state = self.state.lock().unwrap();

        if let Some(file) = state.files.get(name) {
            reply.entry(&TTL, &file_attr(file), Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == ROOT_INODE {
            reply.attr(&TTL, &root_attr());
            return;
        }

        let state = self.state.lock().unwrap();

        if let Some(file) = state.files.values().find(|f| f.inode == ino) {
            reply.attr(&TTL, &file_attr(file));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INODE {
            reply.error(Errno::ENOENT);
            return;
        }

        let state = self.state.lock().unwrap();

        let mut entries = vec![
            (ROOT_INODE, FileType::Directory, ".".to_string()),
            (ROOT_INODE, FileType::Directory, "..".to_string()),
        ];

        for (name, file) in &state.files {
            entries.push((file.inode, FileType::RegularFile, name.clone()));
        }

        entries[2..].sort_by(|a, b| a.2.cmp(&b.2));

        for (index, (inode, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*inode, (index + 1) as u64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mut state = self.state.lock().unwrap();

        let Some(name) = state
            .files
            .iter()
            .find(|(_, file)| file.inode == ino)
            .map(|(name, _)| name.clone())
        else {
            reply.error(Errno::ENOENT);
            return;
        };

        let file = state.files.get_mut(&name).unwrap();

        if let Some(new_mode) = mode {
            file.permissions = (new_mode & 0o777) as u16;
        }

        if let Some(new_size) = size {
            let Ok(new_size) = usize::try_from(new_size) else {
                reply.error(Errno::EFBIG);
                return;
            };

            let old_content = file.content.clone();
            file.content.resize(new_size, 0);

            if self.persist_file(&name, &file.content).is_err() {
                file.content = old_content;
                reply.error(Errno::EIO);
                return;
            }

            file.mtime = SystemTime::now();
        }

        if let Some(time) = atime {
            file.atime = match time {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            };
        }

        if let Some(time) = mtime {
            file.mtime = match time {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            };
        }

        file.ctime = SystemTime::now();

        reply.attr(&TTL, &file_attr(file));
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if parent != ROOT_INODE {
            reply.error(Errno::ENOENT);
            return;
        }

        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };

        if !valid_filename(name) {
            reply.error(Errno::EINVAL);
            return;
        }

        let mut state = self.state.lock().unwrap();

        if state.files.contains_key(name) {
            reply.error(Errno::EEXIST);
            return;
        }

        // Store an encrypted empty file before making it visible.
        if self.persist_file(name, &[]).is_err() {
            reply.error(Errno::EIO);
            return;
        }

        let inode = INodeNo(state.next_inode);
        state.next_inode += 1;

        let permissions = (mode & !umask & 0o777) as u16;
        let now = SystemTime::now();

        let file = FileEntry {
            inode,
            content: Vec::new(),
            permissions,
            atime: now,
            mtime: now,
            ctime: now,
        };

        let attr = file_attr(&file);
        state.files.insert(name.to_string(), file);

        reply.created(
            &TTL,
            &attr,
            Generation(0),
            FileHandle(0),
            FopenFlags::empty(),
        );
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let state = self.state.lock().unwrap();

        if state.files.values().any(|file| file.inode == ino) {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let mut state = self.state.lock().unwrap();

        let Some(file) = state.files.values_mut().find(|f| f.inode == ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        file.atime = SystemTime::now();

        let Ok(start) = usize::try_from(offset) else {
            reply.data(&[]);
            return;
        };

        if start >= file.content.len() {
            reply.data(&[]);
            return;
        }

        let end = start.saturating_add(size as usize).min(file.content.len());

        reply.data(&file.content[start..end]);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut state = self.state.lock().unwrap();

        let Some(name) = state
            .files
            .iter()
            .find(|(_, file)| file.inode == ino)
            .map(|(name, _)| name.clone())
        else {
            reply.error(Errno::ENOENT);
            return;
        };

        let file = state.files.get_mut(&name).unwrap();

        let Ok(start) = usize::try_from(offset) else {
            reply.error(Errno::EFBIG);
            return;
        };

        let Some(end) = start.checked_add(data.len()) else {
            reply.error(Errno::EFBIG);
            return;
        };

        let old_content = file.content.clone();

        if end > file.content.len() {
            file.content.resize(end, 0);
        }

        file.content[start..end].copy_from_slice(data);

        // Persist encrypted data before confirming the write.
        if self.persist_file(&name, &file.content).is_err() {
            file.content = old_content;
            reply.error(Errno::EIO);
            return;
        }

        let now = SystemTime::now();
        file.mtime = now;
        file.ctime = now;

        reply.written(data.len() as u32);
    }
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 100
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

fn encode_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(data.len() * 2);

    for byte in data {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(value.len() / 2);

    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;

        output.push(((high << 4) | low) as u8);
    }

    Some(output)
}

fn set_private_permissions(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn load_or_create_keypair(key_path: &Path, storage_dir: &Path) -> Result<MlKem768KeyPair, String> {
    if key_path.exists() {
        println!("Existing QuantumVault key found.");
        let mut passphrase = rpassword::prompt_password("Enter QuantumVault passphrase: ")
            .map_err(|error| error.to_string())?;

        if passphrase.is_empty() {
            return Err("Passphrase cannot be empty.".to_string());
        }

        let result = unprotect_keypair_file(key_path, passphrase.as_bytes())
            .map_err(|error| format!("Unable to unlock keypair: {:?}", error));

        passphrase.zeroize();

        return result;
    }

    // Never silently generate a replacement key if encrypted data exists.
    let has_existing_data = fs::read_dir(storage_dir)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("qv"));

    if has_existing_data {
        return Err("Encrypted files exist, but the private key is missing. \
             Refusing to generate a replacement key."
            .to_string());
    }

    println!("First-time QuantumVault setup.");
    println!("Create a strong passphrase to protect your private key.");

    let mut passphrase =
        rpassword::prompt_password("Create passphrase: ").map_err(|error| error.to_string())?;

    let mut confirmation =
        rpassword::prompt_password("Confirm passphrase: ").map_err(|error| error.to_string())?;

    if passphrase.is_empty() || passphrase != confirmation {
        passphrase.zeroize();
        confirmation.zeroize();

        return Err("Passphrases are empty or do not match. Please try again.".to_string());
    }

    let keypair =
        mlkem768_keypair().map_err(|error| format!("Key generation failed: {:?}", error))?;

    let save_result = protect_keypair_file(&keypair, passphrase.as_bytes(), key_path)
        .map_err(|error| format!("Unable to protect private key: {:?}", error));

    passphrase.zeroize();
    confirmation.zeroize();

    save_result?;

    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;

    println!("Protected ML-KEM-768 keypair created successfully.");

    Ok(keypair)
}

fn root_attr() -> FileAttr {
    let now = SystemTime::now();

    FileAttr {
        ino: ROOT_INODE,
        size: 0,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

fn file_attr(file: &FileEntry) -> FileAttr {
    let size = file.content.len() as u64;

    FileAttr {
        ino: file.inode,
        size,
        blocks: (size + 511) / 512,
        atime: file.atime,
        mtime: file.mtime,
        ctime: file.ctime,
        crtime: file.ctime,
        kind: FileType::RegularFile,
        perm: file.permissions,
        nlink: 1,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

fn main() {
    let app_dir =
        PathBuf::from(std::env::var("HOME").expect("HOME environment variable is not available"))
            .join(".local")
            .join("share")
            .join("quantumvault");

    let key_dir = app_dir.join("keys");
    let storage_dir = app_dir.join("files");

    fs::create_dir_all(&key_dir).expect("Unable to create QuantumVault key directory");

    fs::create_dir_all(&storage_dir).expect("Unable to create QuantumVault storage directory");

    set_private_permissions(&app_dir).expect("Unable to secure QuantumVault data directory");

    set_private_permissions(&key_dir).expect("Unable to secure key directory");

    set_private_permissions(&storage_dir).expect("Unable to secure encrypted storage directory");

    let key_path = key_dir.join("mlkem768.qvkey");

    let keypair = load_or_create_keypair(&key_path, &storage_dir).unwrap_or_else(|error| {
        panic!("QuantumVault initialization failed: {}", error);
    });

    let filesystem = QuantumVaultFS::new(keypair, storage_dir)
        .expect("Unable to initialize encrypted filesystem");

    let mountpoint = "/tmp/quantumvault_mount";

    fs::create_dir_all(mountpoint).expect("Unable to create FUSE mountpoint");

    println!("Starting QuantumVault Encrypted Filesystem...");
    println!("Mount point: {}", mountpoint);
    println!("Encrypted data directory: {}", app_dir.display());
    println!("File contents are encrypted at rest.");

    let mut config = Config::default();

    config
        .mount_options
        .push(MountOption::FSName("QuantumVault".to_string()));

    fuser::mount(filesystem, mountpoint, &config).expect("Failed to mount QuantumVault filesystem");
}
