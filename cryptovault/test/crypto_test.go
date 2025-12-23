// test/crypto_test.go - Test from-scratch implementations
package test

import (
	"testing"

	"cryptovault/internal/crypto"
	"github.com/stretchr/testify/assert"
)

func TestCaesarCipher(t *testing.T) {
	plaintext := "HELLO WORLD"
	shift := 3

	// Test encryption
	ciphertext := crypto.CaesarEncrypt(plaintext, shift)
	assert.Equal(t, "KHOOR ZRUOG", ciphertext)

	// Test decryption
	decrypted := crypto.CaesarDecrypt(ciphertext, shift)
	assert.Equal(t, plaintext, decrypted)
}

func TestCaesarFrequencyAnalysis(t *testing.T) {
	// Encrypt with known shift
	plaintext := "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
	shift := 7
	ciphertext := crypto.CaesarEncrypt(plaintext, shift)

	// Break it with frequency analysis
	decrypted, foundShift := crypto.CaesarFrequencyAnalysis(ciphertext)

	assert.Equal(t, shift, foundShift)
	assert.Equal(t, plaintext, decrypted)
}

func TestVigenereCipher(t *testing.T) {
	plaintext := "HELLO WORLD"
	key := "KEY"

	// Test encryption
	ciphertext := crypto.VigenereEncrypt(plaintext, key)
	assert.NotEqual(t, plaintext, ciphertext)

	// Test decryption
	decrypted := crypto.VigenereDecrypt(ciphertext, key)
	assert.Equal(t, plaintext, decrypted)
}

func TestVigenereWithLongText(t *testing.T) {
	plaintext := "ATTACKATDAWN"
	key := "LEMON"

	ciphertext := crypto.VigenereEncrypt(plaintext, key)
	assert.Equal(t, "LXFOPVEFRNHR", ciphertext)

	decrypted := crypto.VigenereDecrypt(ciphertext, key)
	assert.Equal(t, plaintext, decrypted)
}
