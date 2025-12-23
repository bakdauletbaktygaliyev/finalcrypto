// internal/files/hash.go
package files

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// CalculateFileHash calculates SHA-256 hash of a file
func CalculateFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyFileIntegrity verifies file hasn't been tampered with
func VerifyFileIntegrity(filepath, expectedHash string) (bool, error) {
	actualHash, err := CalculateFileHash(filepath)
	if err != nil {
		return false, err
	}

	return actualHash == expectedHash, nil
}
