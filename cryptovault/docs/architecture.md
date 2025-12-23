# CryptoVault System Architecture

## Overview
CryptoVault is a comprehensive cryptographic security suite implementing four integrated modules with blockchain-based audit logging.

## System Architecture Diagram

```
┌───────────────────────────────────────────────┐
│               CryptoVault Suite               │
└───────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│              Application Modules               │
└───────────────────────────────────────────────┘
        │                 │                 │
        ▼                 ▼                 ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────────┐
│ Authentication │ │   Messaging     │ │   File Encryption  │
│     Module     │ │     Module      │ │       Module       │
├────────────────┤ ├────────────────┤ ├────────────────────┤
│ • Registration │ │ • ECDH Key Exch │ │ • AES-256-GCM      │
│ • TOTP 2FA     │ │ • AES-256-GCM   │ │ • PBKDF2 KDF       │
│ • Session Mgmt │ │ • ECDSA Signs   │ │ • SHA-256 Hash     │
│ • Argon2id     │ │ • P-256 Curve   │ │ • HMAC Auth        │
└────────────────┘ └────────────────┘ └────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│               Blockchain Ledger               │
├───────────────────────────────────────────────┤
│ • Block Structure                              │
│ • Merkle Trees                                 │
│ • Proof of Work                                │
│ • Audit Trail                                  │
└───────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│              Core Crypto Library               │
├───────────────────────────────────────────────┤
│ • Caesar Cipher (scratch)                      │
│ • Vigenère Cipher (scratch)                    │
│ • SHA-256 (scratch)                            │
└───────────────────────────────────────────────┘

```


## Module Descriptions

### 1. Authentication Module
**Purpose**: Secure user registration and authentication with multi-factor authentication.

**Components**:
- **Password Hashing**: Argon2id with 64MB memory, 4 threads
- **TOTP**: Time-based One-Time Passwords using RFC 6238
- **Session Management**: Token-based sessions with 24-hour expiry
- **Rate Limiting**: Account lockout after 5 failed attempts

**Data Flow**:
1. User provides username + password
2. System validates password strength (12+ chars, mixed case, numbers, special)
3. Password hashed with Argon2id + random salt
4. TOTP secret generated and shown as QR code
5. User credentials stored securely
6. Login requires password + current TOTP code
7. Session token generated on successful login
8. All auth events logged to blockchain

### 2. Messaging Module
**Purpose**: End-to-end encrypted messaging with non-repudiation.

**Components**:
- **Key Exchange**: ECDH using NIST P-256 curve
- **Encryption**: AES-256-GCM with unique nonce per message
- **Signatures**: ECDSA signatures for message authenticity
- **Key Derivation**: HKDF-SHA256 for deriving encryption keys

**Data Flow**:
1. Sender generates ephemeral ECDH key pair
2. Performs ECDH with recipient's public key → shared secret
3. Derives AES key using HKDF(shared_secret)
4. Encrypts message with AES-256-GCM
5. Signs ciphertext with sender's ECDSA private key
6. Package: [ephemeral_pk || nonce || ciphertext || auth_tag || signature]
7. Recipient verifies signature, performs ECDH, decrypts
8. Message send logged to blockchain

### 3. File Encryption Module
**Purpose**: Secure file storage with integrity verification.

**Components**:
- **File Encryption**: AES-256-GCM for confidentiality + authenticity
- **Key Derivation**: PBKDF2-HMAC-SHA256, 100,000 iterations
- **Integrity**: SHA-256 hash + HMAC-SHA256
- **Key Wrapping**: File Encryption Key (FEK) wrapped with master key

**Data Flow**:
1. User provides password
2. Derive master key: PBKDF2(password, random_salt, 100k iterations)
3. Generate random FEK (32 bytes)
4. Encrypt file with AES-256-GCM using FEK
5. Encrypt FEK with master key
6. Calculate SHA-256(original_file)
7. Calculate HMAC-SHA256(encrypted_file, master_key)
8. Store: [salt || nonce || encrypted_FEK || encrypted_file]
9. Store metadata: [file_hash || HMAC]
10. File operations logged to blockchain

### 4. Blockchain Ledger Module
**Purpose**: Immutable audit trail of all security events.

**Components**:
- **Block Structure**: Index, timestamp, transactions, Merkle root, prev hash, nonce
- **Merkle Trees**: Binary tree of transaction hashes with proof generation
- **Proof of Work**: SHA-256 based PoW with adjustable difficulty
- **Transaction Types**: AUTH_*, MESSAGE_*, FILE_*

**Data Flow**:
1. Security event occurs in any module
2. Transaction created with event details (hashed for privacy)
3. Added to pending transaction pool
4. When pool ≥ 5 transactions, mining triggered
5. Build Merkle tree from transactions
6. Find nonce where SHA256(block) has N leading zeros
7. Block added to chain
8. Chain saved to disk

## Security Architecture

### Defense in Depth Layers

1. **Cryptographic Layer**
    - Industry-standard algorithms (AES-256, SHA-256, ECDSA)
    - Proper key derivation (PBKDF2, HKDF)
    - Authenticated encryption (GCM mode)

2. **Authentication Layer**
    - Strong password requirements
    - Multi-factor authentication (TOTP)
    - Rate limiting and account lockout
    - Constant-time comparisons

3. **Integrity Layer**
    - HMAC for file authenticity
    - Digital signatures for messages
    - Blockchain for audit integrity
    - Merkle proofs for verification

4. **Privacy Layer**
    - Hashed identifiers in logs
    - No plaintext storage
    - Encrypted file contents
    - End-to-end encryption

## Data Storage

### Directory Structure
```
data/
├── users/
│   ├── alice.json          # User credentials
│   └── bob.json
├── keys/
│   ├── alice.key           # Private ECDSA keys
│   ├── alice.pub           # Public ECDSA keys
│   └── bob.key
├── messages/
│   ├── alice/
│   │   └── 1234567890_bob.json
│   └── bob/
│       └── 1234567891_alice.json
└── blockchain/
└── chain.json          # Blockchain data
```

## Technology Stack

- **Language**: Go 1.21+
- **CLI Framework**: Cobra + Viper
- **Cryptography**: golang.org/x/crypto
- **TOTP**: github.com/pquerna/otp
- **Testing**: github.com/stretchr/testify

## Performance Considerations

- **PBKDF2**: 100,000 iterations ≈ 100ms on modern CPU
- **Argon2id**: 64MB memory, 4 threads ≈ 50ms
- **AES-GCM**: Hardware accelerated on modern CPUs
- **Blockchain Mining**: Adjustable difficulty (default: 4 leading zeros)