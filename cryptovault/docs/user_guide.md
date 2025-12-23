# CryptoVault User Guide

## Installation

### Prerequisites
- Go 1.21 or higher
- Git

### Install from Source
```bash
# Clone repository
git clone https://github.com/yourusername/cryptovault
cd cryptovault

# Install dependencies
go mod download

# Build
go build -o cryptovault ./cmd/cryptovault

# Install globally (optional)
go install ./cmd/cryptovault
```

## Quick Start

### 1. Register a New User
```bash
# Register with username
./cryptovault auth register -u alice

# You'll be prompted for password
Enter password: ********
Confirm password: ********

# Save the TOTP secret and scan the QR code with your authenticator app
✓ User 'alice' registered successfully!

Setup your authenticator app:
Secret: JBSWY3DPEHPK3PXP
URL: otpauth://totp/CryptoVault:alice?secret=JBSWY3DPEHPK3PXP&issuer=CryptoVault

█████████████████████████████████
█████████████████████████████████
████ ▄▄▄▄▄ █▀█ █▄▀▄▀█ ▄▄▄▄▄ ████
████ █   █ █▀▀▀█ ▄ █ █   █ ████
████ █▄▄▄█ █▀ █▀▀█▀▄█ █▄▄▄█ ████
...
```

### 2. Login
```bash
# Login with TOTP code from your authenticator app
./cryptovault auth login -u alice -t 123456

✓ Successfully logged in as 'alice'
Session token: a1b2c3d4e5f6g7h8...
```

### 3. Send Encrypted Message
```bash
# Send message to another user
./cryptovault message send --to bob --message "Hello Bob! This is encrypted."

✓ Message sent to bob
```

### 4. Receive Messages
```bash
# List all messages
./cryptovault message list

# View messages from specific user
./cryptovault message receive --from alice

From: alice
Time: 2024-12-23 14:30:45
Message: Hello Bob! This is encrypted.
✓ Signature valid
```

### 5. Encrypt File
```bash
# Encrypt a file
./cryptovault file encrypt \
  -i secret_document.pdf \
  -o secret_document.enc \
  -p "MyStrongPassword123!"

✓ File encrypted: secret_document.enc
✓ Metadata saved: secret_document.enc.meta
```

### 6. Decrypt File
```bash
# Decrypt a file
./cryptovault file decrypt \
  -i secret_document.enc \
  -o decrypted_document.pdf \
  -p "MyStrongPassword123!"

✓ HMAC verified
✓ File integrity verified
✓ File decrypted: decrypted_document.pdf
```

### 7. View Blockchain
```bash
# View entire blockchain
./cryptovault blockchain view

# Verify blockchain integrity
./cryptovault blockchain verify

# Search audit log
./cryptovault blockchain search --type AUTH_LOGIN --user alice
```

## Common Workflows

### Complete User Registration Flow
```bash
# 1. Register
./cryptovault auth register -u alice

# 2. Setup authenticator app (Google Authenticator, Authy, etc.)
#    Scan the QR code displayed

# 3. Test login
./cryptovault auth login -u alice -t <TOTP-code>

# 4. Logout when done
./cryptovault auth logout
```

### Secure File Sharing
```bash
# Alice encrypts a file
./cryptovault auth login -u alice -t 123456
./cryptovault file encrypt -i data.txt -o data.enc -p "SharedPass123!"
./cryptovault auth logout

# Bob decrypts the file (with shared password)
./cryptovault auth login -u bob -t 654321
./cryptovault file decrypt -i data.enc -o data.txt -p "SharedPass123!"
./cryptovault auth logout
```

### Message Exchange
```bash
# Alice sends message to Bob
./cryptovault auth login -u alice -t 123456
./cryptovault message send --to bob --message "Meeting at 3pm"
./cryptovault auth logout

# Bob receives and reads message
./cryptovault auth login -u bob -t 654321
./cryptovault message receive --from alice
./cryptovault auth logout
```

## Advanced Features

### Custom Data Directory
```bash
# Use custom data directory
./cryptovault --datadir /secure/vault auth register -u alice
```

### Mining Blockchain Manually
```bash
# Force mine pending transactions
./cryptovault blockchain mine
```

### Export Public Key
```bash
# Get your public key for sharing
./cryptovault message pubkey

Your public key:
BGzE4F1rThrx7Vp3j8K...
```

## Troubleshooting

### "Account locked" Error
If you see account locked error after failed login attempts:
- Wait 15 minutes
- Or contact administrator to manually unlock

### "Invalid TOTP code" Error
- Ensure your device clock is synchronized
- TOTP codes are time-based (valid for 30 seconds)
- Check if you're using the correct secret

### "HMAC verification failed" Error
- File may have been tampered with
- Incorrect password
- Corrupted metadata file

### "Session expired" Error
- Session tokens expire after 24 hours
- Login again with `./cryptovault auth login`

## Security Best Practices

### Password Guidelines
- ✅ Minimum 12 characters
- ✅ Mix of uppercase and lowercase
- ✅ Include numbers
- ✅ Include special characters
- ❌ Don't reuse passwords
- ❌ Don't share passwords

### TOTP Best Practices
- ✅ Use reputable authenticator app
- ✅ Backup your TOTP secret securely
- ✅ Save backup codes in safe place
- ❌ Don't share TOTP codes
- ❌ Don't screenshot QR codes

### File Security
- ✅ Use strong encryption passwords
- ✅ Different passwords for different files
- ✅ Delete original files after encryption
- ✅ Verify HMAC before trusting decrypted files
- ❌ Don't store passwords with encrypted files

## Configuration

### Config File Location
CryptoVault reads configuration from:
- `./cryptovault.yaml`
- `$HOME/.cryptovault.yaml`

### Sample Config
```yaml
datadir: ./data
blockchain:
  difficulty: 4
  auto_mine: true
  min_transactions: 5
auth:
  session_timeout: 24h
  max_failed_attempts: 5
  lockout_duration: 15m
```

## API Documentation

See `architecture.md` for technical details about the cryptographic implementation.

## Support

- GitHub Issues: https://github.com/yourusername/cryptovault/issues
- Email: support@cryptovault.local
- Documentation: https://docs.cryptovault.local