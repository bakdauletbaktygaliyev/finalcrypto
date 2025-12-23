package test

import (
	_ "cryptovault/internal/auth"
	_ "cryptovault/internal/crypto"
	"os"
	"testing"
	"time"

	"cryptovault/internal/vault"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestVault(t *testing.T) (*vault.CryptoVault, string) {
	dataDir := "./test_data_" + time.Now().Format("20060102150405")
	v, err := vault.NewCryptoVault(dataDir)
	require.NoError(t, err)
	return v, dataDir
}

func cleanupTestVault(dataDir string) {
	os.RemoveAll(dataDir)
}

func TestCryptoVaultRegistration(t *testing.T) {
	v, dataDir := setupTestVault(t)
	defer cleanupTestVault(dataDir)

	// Test successful registration
	secret, err := v.Register("alice", "StrongPass123!@#")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Test duplicate registration
	_, err = v.Register("alice", "StrongPass123!@#")
	assert.Error(t, err)

	// Test weak password
	_, err = v.Register("bob", "weak")
	assert.Error(t, err)

	// Verify blockchain logged registration
	chain := v.GetBlockchain()
	assert.Greater(t, len(chain), 0)
}

func TestCryptoVaultLogin(t *testing.T) {
	v, dataDir := setupTestVault(t)
	defer cleanupTestVault(dataDir)

	// Register user
	secret, err := v.Register("alice", "StrongPass123!@#")
	require.NoError(t, err)

	// Generate TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// Test successful login
	token, err := v.Login("alice", "StrongPass123!@#", code, "192.168.1.1")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify session is valid
	err = v.ValidateSession(token)
	assert.NoError(t, err)

	// Test logout
	err = v.Logout(token)
	assert.NoError(t, err)

	// Verify session is now invalid
	err = v.ValidateSession(token)
	assert.Error(t, err)
}

func TestCryptoVaultFileEncryption(t *testing.T) {
	v, dataDir := setupTestVault(t)
	defer cleanupTestVault(dataDir)

	// Register and login
	secret, _ := v.Register("alice", "StrongPass123!@#")
	code, _ := totp.GenerateCode(secret, time.Now())
	v.Login("alice", "StrongPass123!@#", code, "192.168.1.1")

	// Create test file
	testFile := dataDir + "/test.txt"
	testData := []byte("This is a secret message!")
	err := os.WriteFile(testFile, testData, 0644)
	require.NoError(t, err)

	// Encrypt file
	encFile := dataDir + "/test.enc"
	err = v.EncryptFile(testFile, encFile, "FilePass123!")
	assert.NoError(t, err)

	// Verify encrypted file exists
	_, err = os.Stat(encFile)
	assert.NoError(t, err)

	// Decrypt file
	decFile := dataDir + "/test_dec.txt"
	err = v.DecryptFile(encFile, decFile, "FilePass123!")
	assert.NoError(t, err)

	// Verify decrypted content matches original
	decData, err := os.ReadFile(decFile)
	assert.NoError(t, err)
	assert.Equal(t, testData, decData)

	// Test wrong password
	err = v.DecryptFile(encFile, dataDir+"/wrong.txt", "WrongPass!")
	assert.Error(t, err)
}

func TestCryptoVaultMessaging(t *testing.T) {
	v, dataDir := setupTestVault(t)
	defer cleanupTestVault(dataDir)

	// Register two users
	aliceSecret, _ := v.Register("alice", "StrongPass123!@#")
	bobSecret, _ := v.Register("bob", "StrongPass456!@#")

	// Login as Alice
	aliceCode, _ := totp.GenerateCode(aliceSecret, time.Now())
	v.Login("alice", "StrongPass123!@#", aliceCode, "192.168.1.1")

	// Create Bob's messaging module (simulate Bob being registered)
	v2, _ := vault.NewCryptoVault(dataDir)
	bobCode, _ := totp.GenerateCode(bobSecret, time.Now())
	v2.Login("bob", "StrongPass456!@#", bobCode, "192.168.1.2")

	// Alice sends message to Bob
	err := v.SendMessage("bob", "Hello Bob!")
	assert.NoError(t, err)

	// Verify blockchain logged the message
	logs := v.SearchAuditLog("MESSAGE_SEND", "alice")
	assert.Greater(t, len(logs), 0)
}

func TestCryptoVaultBlockchain(t *testing.T) {
	v, dataDir := setupTestVault(t)
	defer cleanupTestVault(dataDir)

	// Perform various operations
	v.Register("alice", "StrongPass123!@#")
	v.Register("bob", "StrongPass456!@#")

	// Mine block
	err := v.MineBlock()
	assert.NoError(t, err)

	// Validate blockchain
	valid := v.ValidateBlockchain()
	assert.True(t, valid)

	// Search audit log
	logs := v.SearchAuditLog("AUTH_REGISTER", "")
	assert.Equal(t, 2, len(logs))
}
