// internal/vault/vault.go
package vault

import (
	"fmt"
	"time"

	"cryptovault/internal/auth"
	"cryptovault/internal/blockchain"
	"cryptovault/internal/files"
	"cryptovault/internal/messaging"
)

// CryptoVault integrates all modules with blockchain logging
type CryptoVault struct {
	Auth        *auth.AuthModule
	Messaging   *messaging.MessagingModule
	Files       *files.FileEncryptionModule
	Blockchain  *blockchain.BlockchainModule
	dataDir     string
	currentUser string
}

// NewCryptoVault creates a new integrated CryptoVault instance
func NewCryptoVault(dataDir string) (*CryptoVault, error) {
	authModule, err := auth.NewAuthModule(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth module: %w", err)
	}

	fileModule := files.NewFileEncryptionModule(dataDir)

	blockchain, err := blockchain.NewBlockchainModule(dataDir, 4)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}

	return &CryptoVault{
		Auth:       authModule,
		Files:      fileModule,
		Blockchain: blockchain,
		dataDir:    dataDir,
	}, nil
}

// Register registers a new user and logs to blockchain
func (v *CryptoVault) Register(username, password string) (string, error) {
	key, err := v.Auth.Register(username, password)
	if err != nil {
		// Log failed registration
		v.Blockchain.AddTransaction("AUTH_REGISTER_FAIL", map[string]interface{}{
			"user_hash": auth.HashForLogging(username),
			"timestamp": time.Now().Unix(),
			"success":   false,
		})
		return "", err
	}

	// Log successful registration
	v.Blockchain.AddTransaction("AUTH_REGISTER", map[string]interface{}{
		"user_hash": auth.HashForLogging(username),
		"timestamp": time.Now().Unix(),
		"success":   true,
	})

	return key.Secret(), nil
}

// Login authenticates user and logs to blockchain
func (v *CryptoVault) Login(username, password, totpCode, ipAddress string) (string, error) {
	token, err := v.Auth.Login(username, password, totpCode)

	// Log login attempt
	v.Blockchain.AddTransaction("AUTH_LOGIN", map[string]interface{}{
		"user_hash": auth.HashForLogging(username),
		"timestamp": time.Now().Unix(),
		"success":   err == nil,
		"ip_hash":   auth.HashForLogging(ipAddress),
	})

	if err != nil {
		return "", err
	}

	// Initialize messaging for this user
	msgModule, err := messaging.NewMessagingModule(v.dataDir, username)
	if err != nil {
		return "", err
	}
	v.Messaging = msgModule
	v.currentUser = username

	return token, nil
}

// Logout logs out user and records to blockchain
func (v *CryptoVault) Logout(token string) error {
	session, err := v.Auth.ValidateSession(token)
	if err != nil {
		return err
	}

	// Log logout
	v.Blockchain.AddTransaction("AUTH_LOGOUT", map[string]interface{}{
		"user_hash": auth.HashForLogging(session.Username),
		"timestamp": time.Now().Unix(),
	})

	return v.Auth.Logout(token)
}

// SendMessage sends encrypted message and logs to blockchain
func (v *CryptoVault) SendMessage(recipient, message string) error {
	if v.Messaging == nil {
		return fmt.Errorf("not logged in")
	}

	err := v.Messaging.SendMessage(recipient, message)

	// Log message send
	v.Blockchain.AddTransaction("MESSAGE_SEND", map[string]interface{}{
		"sender_hash":    auth.HashForLogging(v.currentUser),
		"recipient_hash": auth.HashForLogging(recipient),
		"timestamp":      time.Now().Unix(),
		"success":        err == nil,
		"message_hash":   auth.HashForLogging(message),
	})

	return err
}

// EncryptFile encrypts file and logs to blockchain
func (v *CryptoVault) EncryptFile(inputPath, outputPath, password string) error {
	// Calculate original file hash before encryption
	originalHash, err := files.CalculateFileHash(inputPath)
	if err != nil {
		return err
	}

	err = v.Files.EncryptFile(inputPath, outputPath, password)

	// Calculate encrypted file hash
	var encryptedHash string
	if err == nil {
		encryptedHash, _ = files.CalculateFileHash(outputPath)
	}

	// Log file encryption
	v.Blockchain.AddTransaction("FILE_ENCRYPT", map[string]interface{}{
		"file_hash":      originalHash,
		"user_hash":      auth.HashForLogging(v.currentUser),
		"timestamp":      time.Now().Unix(),
		"success":        err == nil,
		"encrypted_hash": encryptedHash,
	})

	return err
}

// DecryptFile decrypts file and logs to blockchain
func (v *CryptoVault) DecryptFile(inputPath, outputPath, password string) error {
	// Calculate encrypted file hash
	encryptedHash, err := files.CalculateFileHash(inputPath)
	if err != nil {
		return err
	}

	err = v.Files.DecryptFile(inputPath, outputPath, password)

	// Calculate decrypted file hash
	var decryptedHash string
	if err == nil {
		decryptedHash, _ = files.CalculateFileHash(outputPath)
	}

	// Log file decryption
	v.Blockchain.AddTransaction("FILE_DECRYPT", map[string]interface{}{
		"file_hash":      encryptedHash,
		"user_hash":      auth.HashForLogging(v.currentUser),
		"timestamp":      time.Now().Unix(),
		"success":        err == nil,
		"decrypted_hash": decryptedHash,
	})

	return err
}

// ValidateSession checks if session is valid
func (v *CryptoVault) ValidateSession(token string) error {
	_, err := v.Auth.ValidateSession(token)
	return err
}

// MineBlock manually triggers block mining
func (v *CryptoVault) MineBlock() error {
	return v.Blockchain.MineBlock()
}

// GetBlockchain returns the blockchain
func (v *CryptoVault) GetBlockchain() []*blockchain.Block {
	return v.Blockchain.GetChain()
}

// ValidateBlockchain validates the entire chain
func (v *CryptoVault) ValidateBlockchain() bool {
	return v.Blockchain.ValidateChain()
}

// SearchAuditLog searches blockchain for specific events
func (v *CryptoVault) SearchAuditLog(txType, username string) []blockchain.Transaction {
	userHash := ""
	if username != "" {
		userHash = auth.HashForLogging(username)
	}
	return v.Blockchain.SearchTransactions(txType, userHash)
}
