
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption,
    OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INODE: INodeNo = INodeNo::ROOT;
const HELLO_INODE: INodeNo = INodeNo(2);

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
}

impl QuantumVaultFS {
    fn new() -> Self {
        let mut files = HashMap::new();
        let now = SystemTime::now();

        files.insert(
            "hello.txt".to_string(),
            FileEntry {
                inode: HELLO_INODE,
                content: b"Hello from QuantumVault!\n".to_vec(),
                permissions: 0o444,
                atime: now,
                mtime: now,
                ctime: now,
            },
        );

        Self {
            state: Mutex::new(FileSystemState {
                files,
                next_inode: 3,
            }),
        }
    }
}

impl Filesystem for QuantumVaultFS {

    // Find an existing file.
    fn lookup(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
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
            let attr = file_attr(file);

            reply.entry(&TTL, &attr, Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    // Retrieve file or directory attributes.
    fn getattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        if ino == ROOT_INODE {
            reply.attr(&TTL, &root_attr());
            return;
        }

        let state = self.state.lock().unwrap();

        if let Some(file) = state.files.values().find(|f| f.inode == ino) {
            let attr = file_attr(file);
            reply.attr(&TTL, &attr);
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    // List directory contents.
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
            entries.push((
                file.inode,
                FileType::RegularFile,
                name.clone(),
            ));
        }

        entries[2..].sort_by(|a, b| a.2.cmp(&b.2));

        for (index, (inode, kind, name)) in
            entries.iter().enumerate().skip(offset as usize)
        {
            if reply.add(*inode, (index + 1) as u64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    // Change file attributes, size and timestamps.
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

        let Some(file) = state.files.values_mut().find(|f| f.inode == ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        // Update file permissions.
        if let Some(new_mode) = mode {
            file.permissions = (new_mode & 0o777) as u16;
        }

        // Resize or truncate file contents.
        if let Some(new_size) = size {
            let Ok(new_size) = usize::try_from(new_size) else {
                reply.error(Errno::EFBIG);
                return;
            };

            file.content.resize(new_size, 0);
        }

        // Update access timestamp.
        if let Some(time) = atime {
            file.atime = match time {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            };
        }

        // Update modification timestamp.
        if let Some(time) = mtime {
            file.mtime = match time {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            };
        }

        file.ctime = SystemTime::now();

        let attr = file_attr(file);

        reply.attr(&TTL, &attr);
    }

    // Create a new file dynamically.
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

        if name.is_empty() || name == "." || name == ".." {
            reply.error(Errno::EINVAL);
            return;
        }

        let mut state = self.state.lock().unwrap();

        if state.files.contains_key(name) {
            reply.error(Errno::EEXIST);
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

    // Open an existing file.
    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        reply: ReplyOpen,
    ) {
        let state = self.state.lock().unwrap();

        if state.files.values().any(|file| file.inode == ino) {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    // Read file contents.
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

    // Write data into a file.
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

        let Some(file) = state.files.values_mut().find(|f| f.inode == ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let Ok(start) = usize::try_from(offset) else {
            reply.error(Errno::EFBIG);
            return;
        };

        let Some(end) = start.checked_add(data.len()) else {
            reply.error(Errno::EFBIG);
            return;
        };

        if end > file.content.len() {
            file.content.resize(end, 0);
        }

        file.content[start..end].copy_from_slice(data);

        let now = SystemTime::now();
        file.mtime = now;
        file.ctime = now;

        reply.written(data.len() as u32);
    }
}

// Attributes for the root directory.
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

// Attributes for regular files.
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
    let mountpoint = "/tmp/quantumvault_mount";

    println!("Starting QuantumVault Virtual Filesystem...");
    println!("Mount point: {}", mountpoint);

    let mut config = Config::default();

    config.mount_options.push(
        MountOption::FSName("QuantumVault".to_string()),
    );

    fuser::mount(
        QuantumVaultFS::new(),
        mountpoint,
        &config,
    )
    .expect("Failed to mount QuantumVault filesystem");
}
