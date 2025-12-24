package test

import (
	"cryptovault/internal/auth"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestAuthModule(t *testing.T) {
	dataDir := "./test_data"
	defer os.RemoveAll(dataDir)

	authModule, err := auth.NewAuthModule(dataDir)
	assert.NoError(t, err)

	// Test registration
	key, err := authModule.Register("testuser", "Test123!@#$")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// Test weak password
	_, err = authModule.Register("weak", "weak")
	assert.Error(t, err)

}
