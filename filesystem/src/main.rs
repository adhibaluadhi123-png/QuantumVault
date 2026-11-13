
use fuser::{
    Config, Errno, FileAttr, FileType, Filesystem,
    Generation, INodeNo, LockOwner, MountOption,
    OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, Request, FileHandle,
};

use std::ffi::OsStr;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);

const ROOT_INODE: INodeNo = INodeNo::ROOT;
const HELLO_INODE: INodeNo = INodeNo(2);

struct QuantumVaultFS;

impl Filesystem for QuantumVaultFS {
    fn lookup(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        if parent == ROOT_INODE && name == OsStr::new("hello.txt") {
            let attr = hello_attr();

            reply.entry(&TTL, &attr, Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        match ino {
            ROOT_INODE => reply.attr(&TTL, &root_attr()),
            HELLO_INODE => reply.attr(&TTL, &hello_attr()),
            _ => reply.error(Errno::ENOENT),
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

        let entries = [
            (ROOT_INODE, FileType::Directory, "."),
            (ROOT_INODE, FileType::Directory, ".."),
            (HELLO_INODE, FileType::RegularFile, "hello.txt"),
        ];

        for (index, (inode, kind, name)) in
            entries.iter().enumerate().skip(offset as usize)
        {
            if reply.add(*inode, (index + 1) as u64, *kind, name) {
                break;
            }
        }

        reply.ok();
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
        if ino != HELLO_INODE {
            reply.error(Errno::ENOENT);
            return;
        }

        let content = b"Hello from QuantumVault!\n";
        let start = offset as usize;

        if start >= content.len() {
            reply.data(&[]);
            return;
        }

        let end = (start + size as usize).min(content.len());

        reply.data(&content[start..end]);
    }
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

fn hello_attr() -> FileAttr {
    let now = SystemTime::now();

    FileAttr {
        ino: HELLO_INODE,
        size: 25,
        blocks: 1,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::RegularFile,
        perm: 0o444,
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

    config.mount_options.push(MountOption::RO);
    config.mount_options.push(
        MountOption::FSName("QuantumVault".to_string())
    );

    fuser::mount(QuantumVaultFS, mountpoint, &config)
        .expect("Failed to mount QuantumVault filesystem");
}
