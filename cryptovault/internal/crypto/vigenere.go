package crypto

import (
	"strings"
	"unicode"
)

// VigenereEncrypt encrypts text using Vigenère cipher
func VigenereEncrypt(plaintext, key string) string {
	key = strings.ToUpper(key)
	var result strings.Builder
	keyIndex := 0

	for _, char := range plaintext {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}

			shift := int(key[keyIndex%len(key)] - 'A')
			encrypted := (int(char-base) + shift) % 26
			result.WriteRune(rune(base + int32(encrypted)))
			keyIndex++
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// VigenereDecrypt decrypts Vigenère cipher
func VigenereDecrypt(ciphertext, key string) string {
	key = strings.ToUpper(key)
	var result strings.Builder
	keyIndex := 0

	for _, char := range ciphertext {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}

			shift := int(key[keyIndex%len(key)] - 'A')
			decrypted := (int(char-base) - shift + 26) % 26
			result.WriteRune(rune(base + int32(decrypted)))
			keyIndex++
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}
