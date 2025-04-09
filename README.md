# Secure Password Manager

A secure command-line password manager written in Rust that uses AES-GCM encryption for storing passwords.

## Features

- Secure password storage using AES-GCM encryption
- Master password protection
- Command-line interface for easy management
- Secure password entry using `rpassword`
- Automatic storage in system-appropriate data directory

## Security Features

1. **AES-GCM Encryption**: Uses the AES-GCM (Galois/Counter Mode) algorithm for authenticated encryption
2. **Secure Key Derivation**: Uses Blake3 for key derivation from the master password
3. **Secure Memory Handling**: Uses `zeroize` for secure memory wiping
4. **Secure Password Input**: Uses `rpassword` for secure password entry without echo
5. **Random Nonce Generation**: Uses cryptographically secure random number generation for nonces

## Usage

The password manager provides the following commands:

### Add a new password entry
```bash
cargo run -- add -n "entry_name" -u "username"
```

### List all password entries
```bash
cargo run -- list
```

### Get a specific password entry
```bash
cargo run -- get -n "entry_name"
```

### Remove a password entry
```bash
cargo run -- remove -n "entry_name"
```

## Implementation Details

### Data Storage

The password manager stores encrypted data in a system-appropriate data directory:
- Windows: `%APPDATA%\com.secure.password-manager\data\`
- macOS: `~/Library/Application Support/com.secure.password-manager/`
- Linux: `~/.local/share/com.secure.password-manager/`

### Encryption Process

1. **Key Derivation**: The master password is used to derive a 256-bit key using Blake3
2. **Data Serialization**: Password entries are serialized to JSON
3. **Encryption**: The JSON data is encrypted using AES-GCM with a random nonce
4. **Storage**: The nonce and encrypted data are stored together in the data file

### Security Considerations

- The master password is never stored
- All sensitive data is encrypted before storage
- Memory is securely wiped when no longer needed
- Passwords are entered securely without echo
- Each encryption operation uses a unique nonce

## Dependencies

- `aes-gcm`: For AES-GCM encryption
- `rand`: For secure random number generation
- `rpassword`: For secure password input
- `serde`: For data serialization
- `directories`: For system-appropriate data storage
- `clap`: For command-line argument parsing
- `zeroize`: For secure memory wiping

## Building

```bash
cargo build --release
```

## Security Notes

- Keep your master password secure and never share it
- The password manager is only as secure as your master password
- Make sure to use a strong master password
- Consider using a password manager to store your master password 