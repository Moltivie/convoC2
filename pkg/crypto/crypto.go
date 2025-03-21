package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	mrand "math/rand"
	"time"
)

// Time window for key rotation (helps counter replay attacks)
const (
	KeyRotationHours = 24
)

// DeriveKey creates a deterministic AES key from agent ID with time-based rotation
func DeriveKey(agentID string) []byte {
	// Get current time window (day of year)
	timeComponent := time.Now().UTC().YearDay()

	// Create a dynamic salt component based on time period
	timeSalt := fmt.Sprintf("%d", timeComponent/KeyRotationHours)

	// Create a seed combining static and time components
	seed := fmt.Sprintf("convoC2-KeyDerivation-%s-%s", agentID, timeSalt)

	// Generate a 256-bit key using SHA-256
	hash := sha256.Sum256([]byte(seed))
	return hash[:]
}

// Encrypt data with AES-256-GCM using derived key
func Encrypt(plaintext, agentID string) (string, error) {
	key := DeriveKey(agentID)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce using random data
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}

	// Add small random padding to vary ciphertext length
	padding := make([]byte, mrand.Intn(16))
	if _, err = io.ReadFull(crand.Reader, padding); err != nil {
		return "", err
	}
	paddedText := append([]byte(plaintext), padding...)

	// Prepend padding length as single byte
	paddedText = append([]byte{byte(len(padding))}, paddedText...)

	// Encrypt and authenticate
	ciphertext := aesGCM.Seal(nonce, nonce, paddedText, nil)

	// Encode using standard URL-safe base64
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt data with AES-256-GCM using derived key
func Decrypt(encryptedStr, agentID string) (string, error) {
	key := DeriveKey(agentID)

	// Try current key window first
	plaintext, err := tryDecrypt(encryptedStr, key)
	if err == nil {
		return plaintext, nil
	}

	// If failed, try previous time window
	timeComponent := time.Now().UTC().YearDay() - KeyRotationHours
	timeSalt := fmt.Sprintf("%d", timeComponent/KeyRotationHours)
	seed := fmt.Sprintf("convoC2-KeyDerivation-%s-%s", agentID, timeSalt)
	prevKey := sha256.Sum256([]byte(seed))

	return tryDecrypt(encryptedStr, prevKey[:])
}

// Helper function that tries to decrypt with a specific key
func tryDecrypt(encryptedStr string, key []byte) (string, error) {
	// Decode using standard URL-safe base64
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]

	paddedText, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	paddingLen := int(paddedText[0])
	messageLen := len(paddedText) - 1 - paddingLen

	return string(paddedText[1 : messageLen+1]), nil
}
