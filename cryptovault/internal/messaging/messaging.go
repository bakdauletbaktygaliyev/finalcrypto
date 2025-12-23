// internal/messaging/messaging.go (COMPLETE VERSION)
package messaging

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Message represents an encrypted message
type Message struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	Nonce       []byte    `json:"nonce"`
	Ciphertext  []byte    `json:"ciphertext"`
	AuthTag     []byte    `json:"auth_tag"`
	Signature   []byte    `json:"signature"`
	Timestamp   time.Time `json:"timestamp"`
	EphemeralPK []byte    `json:"ephemeral_pk"`
}

// KeyPair represents a user's ECDSA key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// MessagingModule handles secure messaging operations
type MessagingModule struct {
	dataDir  string
	keyPair  *KeyPair
	username string
}

// NewMessagingModule creates a new messaging module
func NewMessagingModule(dataDir, username string) (*MessagingModule, error) {
	msgDir := filepath.Join(dataDir, "messages")
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create messages directory: %w", err)
	}

	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Load or generate key pair
	keyPair, err := loadOrGenerateKeyPair(filepath.Join(keysDir, username+".key"))
	if err != nil {
		return nil, err
	}

	// Save public key
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), keyPair.PublicKey.X, keyPair.PublicKey.Y)
	pubKeyPath := filepath.Join(keysDir, username+".pub")
	if err := os.WriteFile(pubKeyPath, []byte(base64.StdEncoding.EncodeToString(pubKeyBytes)), 0644); err != nil {
		return nil, err
	}

	return &MessagingModule{
		dataDir:  dataDir,
		keyPair:  keyPair,
		username: username,
	}, nil
}

// loadOrGenerateKeyPair loads existing key pair or generates new one
func loadOrGenerateKeyPair(keyPath string) (*KeyPair, error) {
	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		var keyData struct {
			D []byte `json:"d"`
			X []byte `json:"x"`
			Y []byte `json:"y"`
		}
		if err := json.Unmarshal(data, &keyData); err == nil {
			privateKey := new(ecdsa.PrivateKey)
			privateKey.D = new(big.Int).SetBytes(keyData.D)
			privateKey.PublicKey.Curve = elliptic.P256()
			privateKey.PublicKey.X = new(big.Int).SetBytes(keyData.X)
			privateKey.PublicKey.Y = new(big.Int).SetBytes(keyData.Y)

			return &KeyPair{
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
			}, nil
		}
	}

	// Generate new key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Save key pair
	keyData := struct {
		D []byte `json:"d"`
		X []byte `json:"x"`
		Y []byte `json:"y"`
	}{
		D: privateKey.D.Bytes(),
		X: privateKey.PublicKey.X.Bytes(),
		Y: privateKey.PublicKey.Y.Bytes(),
	}

	data, err := json.Marshal(keyData)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// deriveSharedSecret performs ECDH key exchange
func (m *MessagingModule) deriveSharedSecret(recipientPubKey *ecdsa.PublicKey) ([]byte, []byte, error) {
	// Generate ephemeral key pair for this message
	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Perform ECDH
	x, _ := recipientPubKey.Curve.ScalarMult(recipientPubKey.X, recipientPubKey.Y, ephemeralPriv.D.Bytes())
	sharedSecret := x.Bytes()

	// Derive encryption key using HKDF
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("CryptoVault-Message-Key"))
	key := make([]byte, 32)
	if _, err := hkdf.Read(key); err != nil {
		return nil, nil, err
	}

	// Return key and ephemeral public key
	ephemeralPK := elliptic.Marshal(elliptic.P256(), ephemeralPriv.PublicKey.X, ephemeralPriv.PublicKey.Y)

	return key, ephemeralPK, nil
}

// SendMessage encrypts and sends a message to a recipient
func (m *MessagingModule) SendMessage(recipientUsername, message string) error {
	// Load recipient's public key
	recipientPubKey, err := m.loadPublicKey(recipientUsername)
	if err != nil {
		return fmt.Errorf("failed to load recipient public key: %w", err)
	}

	// Derive shared secret and get ephemeral public key
	encKey, ephemeralPK, err := m.deriveSharedSecret(recipientPubKey)
	if err != nil {
		return err
	}

	// Encrypt message using AES-256-GCM
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(message), nil)

	// Split ciphertext and auth tag
	authTagSize := aesGCM.Overhead()
	ct := ciphertext[:len(ciphertext)-authTagSize]
	authTag := ciphertext[len(ciphertext)-authTagSize:]

	// Sign the message
	msgHash := sha256.Sum256(ct)
	signature, err := ecdsa.SignASN1(rand.Reader, m.keyPair.PrivateKey, msgHash[:])
	if err != nil {
		return err
	}

	// Create message object
	msg := &Message{
		From:        m.username,
		To:          recipientUsername,
		Nonce:       nonce,
		Ciphertext:  ct,
		AuthTag:     authTag,
		Signature:   signature,
		Timestamp:   time.Now(),
		EphemeralPK: ephemeralPK,
	}

	// Save message
	if err := m.saveMessage(msg); err != nil {
		return err
	}

	return nil
}

// ReceiveMessages retrieves messages for the current user
func (m *MessagingModule) ReceiveMessages(fromUser string) ([]*Message, error) {
	msgDir := filepath.Join(m.dataDir, "messages", m.username)

	files, err := os.ReadDir(msgDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var messages []*Message
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(msgDir, file.Name()))
		if err != nil {
			continue
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		if fromUser == "" || msg.From == fromUser {
			messages = append(messages, &msg)
		}
	}

	return messages, nil
}

// DecryptMessage decrypts a received message
func (m *MessagingModule) DecryptMessage(msg *Message) (string, error) {
	// Load sender's public key
	senderPubKey, err := m.loadPublicKey(msg.From)
	if err != nil {
		return "", fmt.Errorf("failed to load sender public key: %w", err)
	}

	// Verify signature
	msgHash := sha256.Sum256(msg.Ciphertext)
	if !ecdsa.VerifyASN1(senderPubKey, msgHash[:], msg.Signature) {
		return "", errors.New("invalid message signature")
	}

	// Reconstruct shared secret using ephemeral public key
	x, y := elliptic.Unmarshal(elliptic.P256(), msg.EphemeralPK)
	if x == nil {
		return "", errors.New("invalid ephemeral public key")
	}

	// Perform ECDH with our private key
	sharedX, _ := elliptic.P256().ScalarMult(x, y, m.keyPair.PrivateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive same encryption key
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("CryptoVault-Message-Key"))
	key := make([]byte, 32)
	if _, err := hkdfReader.Read(key); err != nil {
		return "", err
	}

	// Decrypt message
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Reconstruct full ciphertext with auth tag
	fullCiphertext := append(msg.Ciphertext, msg.AuthTag...)

	plaintext, err := aesGCM.Open(nil, msg.Nonce, fullCiphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: message tampered or wrong key")
	}

	return string(plaintext), nil
}

// GetPublicKey returns the user's public key in base64
func (m *MessagingModule) GetPublicKey() string {
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), m.keyPair.PublicKey.X, m.keyPair.PublicKey.Y)
	return base64.StdEncoding.EncodeToString(pubKeyBytes)
}

// loadPublicKey loads a user's public key
func (m *MessagingModule) loadPublicKey(username string) (*ecdsa.PublicKey, error) {
	keyPath := filepath.Join(m.dataDir, "keys", username+".pub")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return nil, errors.New("invalid public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// saveMessage saves a message to storage
func (m *MessagingModule) saveMessage(msg *Message) error {
	msgDir := filepath.Join(m.dataDir, "messages", msg.To)
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return err
	}

	filename := fmt.Sprintf("%d_%s.json", msg.Timestamp.Unix(), msg.From)
	msgPath := filepath.Join(msgDir, filename)

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return os.WriteFile(msgPath, data, 0600)
}
