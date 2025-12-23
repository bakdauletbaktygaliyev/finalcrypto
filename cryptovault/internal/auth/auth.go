// internal/auth/auth.go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// User represents a registered user
type User struct {
	Username       string    `json:"username"`
	PasswordHash   []byte    `json:"password_hash"`
	Salt           []byte    `json:"salt"`
	TOTPSecret     string    `json:"totp_secret"`
	BackupCodes    []string  `json:"backup_codes"`
	CreatedAt      time.Time `json:"created_at"`
	FailedAttempts int       `json:"failed_attempts"`
	LockedUntil    time.Time `json:"locked_until"`
}

// Session represents an active session
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthModule handles authentication operations
type AuthModule struct {
	dataDir  string
	sessions map[string]*Session
}

// NewAuthModule creates a new authentication module
func NewAuthModule(dataDir string) (*AuthModule, error) {
	usersDir := filepath.Join(dataDir, "users")
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create users directory: %w", err)
	}

	return &AuthModule{
		dataDir:  dataDir,
		sessions: make(map[string]*Session),
	}, nil
}

// ValidatePasswordStrength checks if password meets security requirements
func (a *AuthModule) ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters long")
	}

	var (
		hasUpper   = regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower   = regexp.MustCompile(`[a-z]`).MatchString(password)
		hasNumber  = regexp.MustCompile(`[0-9]`).MatchString(password)
		hasSpecial = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};:'",.<>?]`).MatchString(password)
	)

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain uppercase, lowercase, number, and special character")
	}

	return nil
}

// HashPassword creates a secure hash using Argon2id
func (a *AuthModule) HashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// GenerateBackupCodes creates secure backup codes for 2FA
func (a *AuthModule) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		codes[i] = base64.RawStdEncoding.EncodeToString(bytes)
	}
	return codes, nil
}

// Register creates a new user account
func (a *AuthModule) Register(username, password string) (*otp.Key, error) {
	// Validate password strength
	if err := a.ValidatePasswordStrength(password); err != nil {
		return nil, err
	}

	// Check if user exists
	if _, err := a.loadUser(username); err == nil {
		return nil, errors.New("username already exists")
	}

	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password
	passwordHash := a.HashPassword(password, salt)

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CryptoVault",
		AccountName: username,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate backup codes
	backupCodes, err := a.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Create user
	user := &User{
		Username:       username,
		PasswordHash:   passwordHash,
		Salt:           salt,
		TOTPSecret:     key.Secret(),
		BackupCodes:    backupCodes,
		CreatedAt:      time.Now(),
		FailedAttempts: 0,
	}

	// Save user
	if err := a.saveUser(user); err != nil {
		return nil, err
	}

	return key, nil
}

// Login authenticates a user and creates a session
func (a *AuthModule) Login(username, password, totpCode string) (string, error) {
	// Load user
	user, err := a.loadUser(username)
	if err != nil {
		return "", errors.New("invalid credentials")
	}

	// Check if account is locked
	if time.Now().Before(user.LockedUntil) {
		return "", fmt.Errorf("account locked until %s", user.LockedUntil.Format(time.RFC3339))
	}

	// Verify password with constant-time comparison
	passwordHash := a.HashPassword(password, user.Salt)
	if subtle.ConstantTimeCompare(passwordHash, user.PasswordHash) != 1 {
		user.FailedAttempts++
		if user.FailedAttempts >= 5 {
			user.LockedUntil = time.Now().Add(15 * time.Minute)
		}
		a.saveUser(user)
		return "", errors.New("invalid credentials")
	}

	// Verify TOTP
	valid := totp.Validate(totpCode, user.TOTPSecret)
	if !valid {
		// Check backup codes
		validBackup := false
		for i, code := range user.BackupCodes {
			if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode)) == 1 {
				// Remove used backup code
				user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
				validBackup = true
				break
			}
		}
		if !validBackup {
			return "", errors.New("invalid TOTP code")
		}
	}

	// Reset failed attempts
	user.FailedAttempts = 0
	user.LockedUntil = time.Time{}
	a.saveUser(user)

	// Generate session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create session
	session := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	a.sessions[token] = session

	return token, nil
}

// ValidateSession checks if a session token is valid
func (a *AuthModule) ValidateSession(token string) (*Session, error) {
	session, ok := a.sessions[token]
	if !ok {
		return nil, errors.New("invalid session")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(a.sessions, token)
		return nil, errors.New("session expired")
	}

	return session, nil
}

// Logout invalidates a session
func (a *AuthModule) Logout(token string) error {
	delete(a.sessions, token)
	return nil
}

// loadUser loads a user from storage
func (a *AuthModule) loadUser(username string) (*User, error) {
	userFile := filepath.Join(a.dataDir, "users", username+".json")
	data, err := os.ReadFile(userFile)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// saveUser saves a user to storage
func (a *AuthModule) saveUser(user *User) error {
	userFile := filepath.Join(a.dataDir, "users", user.Username+".json")
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}

	return os.WriteFile(userFile, data, 0600)
}

// HashForLogging creates a privacy-preserving hash for logging
func HashForLogging(data string) string {
	hash := sha3.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}
