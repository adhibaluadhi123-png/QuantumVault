# QuantumVault – Virtual Filesystem

## Overview

This module implements the virtual filesystem component of QuantumVault using Rust and FUSE3.

It provides a userspace filesystem that supports dynamic file creation, reading, writing, and in-memory file storage.

## Technologies

- Rust
- Cargo
- FUSE3
- fuser Rust crate
- Linux (Ubuntu / WSL2)

## Responsibilities

- Create and mount a virtual filesystem.
- Handle file lookup and directory listing.
- Dynamically create files.
- Support file opening, reading, and writing.
- Handle file resizing and timestamp updates.
- Maintain file contents in memory.
- Prepare the filesystem for future integration with the post-quantum cryptography engine.

## Current Progress

### Day 1 – Project Initialization
- Created the Rust filesystem project.
- Configured Cargo and project structure.
- Added project documentation.

### Day 2 – Basic FUSE Implementation
- Integrated the fuser crate.
- Implemented the basic FUSE filesystem.
- Mounted the virtual filesystem.
- Implemented basic file lookup, attributes, directory listing, and reading.
- Tested the `hello.txt` file.

### Day 3 – Dynamic File Creation and In-Memory Storage
- Implemented dynamic file creation using `create()`.
- Implemented file opening using `open()`.
- Implemented file writing using `write()`.
- Implemented file reading using `read()`.
- Implemented file resizing and timestamp handling using `setattr()`.
- Added in-memory file storage using `HashMap` and `Mutex`.
- Successfully tested creation, writing, reading, and overwriting of multiple files.

## Current Limitations

- File contents are stored in RAM and are not persistent.
- Post-quantum encryption and decryption are not integrated yet.
- File deletion and directory creation are not implemented yet.

## Next Steps

- Integrate the filesystem write operation with the cryptographic engine.
- Store encrypted file data.
- Implement decryption during file reads.
- Integrate with the key management module.
