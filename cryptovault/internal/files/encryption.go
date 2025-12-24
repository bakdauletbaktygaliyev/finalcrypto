package files

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

type EncryptedFile struct {
	Salt         []byte `json:"salt"`
	Nonce        []byte `json:"nonce"`
	FileHash     []byte `json:"file_hash"`
	HMAC         []byte `json:"hmac"`
	EncryptedFEK []byte `json:"encrypted_fek"`
}

type FileEncryptionModule struct {
	dataDir string
}

func NewFileEncryptionModule(dataDir string) *FileEncryptionModule {
	return &FileEncryptionModule{dataDir: dataDir}
}

// EncryptFile encrypts a file with password-derived key
func (f *FileEncryptionModule) EncryptFile(inputPath, outputPath, password string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	fileHash := sha256.Sum256(plaintext)

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	masterKey := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	fek := make([]byte, 32)
	if _, err := rand.Read(fek); err != nil {
		return err
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}

	fekNonce := make([]byte, 12)
	if _, err := rand.Read(fekNonce); err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	encryptedFEK := aesGCM.Seal(nil, fekNonce, fek, nil)

	fileBlock, err := aes.NewCipher(fek)
	if err != nil {
		return err
	}

	fileNonce := make([]byte, 12)
	if _, err := rand.Read(fileNonce); err != nil {
		return err
	}

	fileGCM, err := cipher.NewGCM(fileBlock)
	if err != nil {
		return err
	}

	ciphertext := fileGCM.Seal(nil, fileNonce, plaintext, nil)

	mac := hmac.New(sha256.New, masterKey)
	mac.Write(ciphertext)
	filHMAC := mac.Sum(nil)

	metadata := EncryptedFile{
		Salt:         salt,
		Nonce:        fileNonce,
		FileHash:     fileHash[:],
		HMAC:         filHMAC,
		EncryptedFEK: encryptedFEK,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	metadataPath := outputPath + ".meta"
	if err := os.WriteFile(metadataPath, metadataBytes, 0600); err != nil {
		return err
	}

	return os.WriteFile(outputPath, ciphertext, 0600)
}

// DecryptFile decrypts an encrypted file
func (f *FileEncryptionModule) DecryptFile(inputPath, outputPath, password string) error {
	metadataPath := inputPath + ".meta"
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return err
	}

	var metadata EncryptedFile
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return err
	}

	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	masterKey := pbkdf2.Key([]byte(password), metadata.Salt, 100000, 32, sha256.New)

	mac := hmac.New(sha256.New, masterKey)
	mac.Write(ciphertext)
	expectedHMAC := mac.Sum(nil)

	if !hmac.Equal(expectedHMAC, metadata.HMAC) {
		return errors.New("HMAC verification failed: file may be tampered")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	fek, err := aesGCM.Open(nil, metadata.Nonce[:12], metadata.EncryptedFEK, nil)
	if err != nil {
		return err
	}

	fileBlock, err := aes.NewCipher(fek)
	if err != nil {
		return err
	}

	fileGCM, err := cipher.NewGCM(fileBlock)
	if err != nil {
		return err
	}

	plaintext, err := fileGCM.Open(nil, metadata.Nonce, ciphertext, nil)
	if err != nil {
		return errors.New("decryption failed: wrong password or corrupted file")
	}

	fileHash := sha256.Sum256(plaintext)
	if !hmac.Equal(fileHash[:], metadata.FileHash) {
		return errors.New("file integrity check failed")
	}

	// Write decrypted file
	return os.WriteFile(outputPath, plaintext, 0600)
}
