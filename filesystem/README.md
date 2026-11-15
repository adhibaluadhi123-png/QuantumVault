
## Day 4 – Filesystem Testing and Validation

### Completed Tasks
- Tested creation and management of multiple files.
- Verified offset-based file reading.
- Verified offset-based file writing.
- Tested file truncation.
- Tested large-file operations using a 108 KB test file.
- Tested handling of nonexistent files.
- Verified reading beyond EOF returns zero bytes.
- Tested operations on an existing file.

### Test Results
All the above test cases completed successfully.

### Current Limitations
- File contents are stored in memory.
- Data is not persistent after unmounting.
- Encryption and decryption are not integrated yet.
- Directory creation and file deletion are not implemented yet.

### Next Steps
- Improve filesystem operation coverage.
- Prepare the write interface for integration with the PQC cryptographic engine.
- Coordinate the data exchange format with the cryptography team.
