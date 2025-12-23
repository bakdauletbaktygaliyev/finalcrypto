package crypto

import (
	"strings"
	"unicode"
)

// CaesarEncrypt encrypts text using Caesar cipher
func CaesarEncrypt(plaintext string, shift int) string {
	shift = shift % 26
	var result strings.Builder

	for _, char := range plaintext {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}
			shifted := (int(char-base) + shift) % 26
			result.WriteRune(rune(base + int32(shifted)))
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// CaesarDecrypt decrypts Caesar cipher
func CaesarDecrypt(ciphertext string, shift int) string {
	return CaesarEncrypt(ciphertext, 26-shift)
}

// CaesarFrequencyAnalysis breaks Caesar cipher using frequency analysis
func CaesarFrequencyAnalysis(ciphertext string) (string, int) {
	englishFreq := map[rune]float64{
		'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
		'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
	}

	bestShift := 0
	bestScore := 0.0

	for shift := 0; shift < 26; shift++ {
		decrypted := CaesarDecrypt(ciphertext, shift)
		score := 0.0

		freq := make(map[rune]int)
		total := 0
		for _, char := range strings.ToLower(decrypted) {
			if unicode.IsLetter(char) {
				freq[char]++
				total++
			}
		}

		for char, count := range freq {
			if expectedFreq, ok := englishFreq[char]; ok {
				actualFreq := float64(count) / float64(total) * 100
				score += expectedFreq * actualFreq
			}
		}

		if score > bestScore {
			bestScore = score
			bestShift = shift
		}
	}

	return CaesarDecrypt(ciphertext, bestShift), bestShift
}
