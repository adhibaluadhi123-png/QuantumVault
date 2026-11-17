# Day 5 – QuantumVault Filesystem Architecture Review

## 1. Objective

The objective of Day 5 was to review the existing Rust-based FUSE filesystem architecture and understand how it can be extended to support post-quantum cryptographic integration.

## 2. Existing Filesystem Architecture

The filesystem currently consists of three main structures.

### FileEntry

Stores information about individual files:

- Inode number
- File content
- File permissions
- Access time (atime)
- Modification time (mtime)
- Change time (ctime)

### FileSystemState

Maintains the filesystem's internal state:

- `HashMap` for storing files.
- `next_inode` for generating inode numbers.

### QuantumVaultFS

- Manages the filesystem state.
- Uses `Mutex` for thread-safe access.
- Handles filesystem operations through FUSE.

## 3. Important Filesystem Operations Reviewed

| Operation | Purpose |
|---|---|
| `read()` | Reads file contents using inode and offset. |
| `write()` | Writes data into files. |
| `getattr()` | Retrieves file metadata. |
| `setattr()` | Updates permissions, file size and timestamps. |

## 4. Current Implementation Limitations

The architecture review identified the following limitations:

- File contents are stored in memory.
- File contents are currently stored as plaintext.
- Data is not persistent after the filesystem process exits.
- Post-quantum cryptography has not yet been integrated.
- Encrypted storage will require additional metadata management.

## 5. Preparation for Cryptographic Integration

The following changes will be required in future development:

1. Integrate the cryptographic engine developed by Member 2.
2. Encrypt file data before storing it.
3. Decrypt file data when it is read.
4. Maintain appropriate metadata for encrypted files.
5. Separate logical file size from encrypted storage size.
6. Coordinate the Rust FUSE interface with the C cryptographic engine.

## 6. Important Technical Consideration

ML-KEM is intended for key encapsulation rather than direct encryption of large files. A symmetric encryption algorithm will be needed for file contents, using a key derived from the ML-KEM shared secret.

## 7. Day 5 Outcome

- Reviewed the existing filesystem architecture.
- Understood the responsibilities of the main filesystem structures.
- Examined the read, write and metadata operations.
- Identified current implementation limitations.
- Prepared the architecture for future cryptographic integration.

**Status:** Day 5 architecture review completed.

**Next Step:** Begin Rust–C FFI integration and prepare the filesystem for communication with the cryptographic engine.
