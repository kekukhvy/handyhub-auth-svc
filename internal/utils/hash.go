package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"handyhub-auth-svc/internal/models"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type PasswordHasher interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(password, hash string) bool
}

type BcryptHasher struct {
	Cost int
}

type Argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		memory:      64 * 1024, // 64 MB
		iterations:  3,         // 3 iterations
		parallelism: 2,         // 2 threads
		saltLength:  16,        // 16 bytes salt
		keyLength:   32,        // 32 bytes key
	}
}

func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{Cost: cost}
}

func (b *BcryptHasher) HashPassword(password string) (string, error) {

	if len(password) == 0 {
		return "", models.ErrInvalidPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), b.Cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedPassword), nil
}

func (b *BcryptHasher) ComparePasswords(hashedPassword, plainPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	return err == nil
}

func (a *Argon2Hasher) HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", models.ErrInvalidPassword
	}

	// Generate random salt
	salt, err := generateRandomBytes(a.saltLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password using Argon2
	hash := argon2.IDKey([]byte(password), salt, a.iterations, a.memory, a.parallelism, a.keyLength)

	// Encode salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, a.memory, a.iterations, a.parallelism, b64Salt, b64Hash)

	return encoded, nil
}

func (a *Argon2Hasher) ComparePasswords(hashedPassword, plainPassword string) bool {
	if len(hashedPassword) == 0 || len(plainPassword) == 0 {
		return false
	}

	// Parse the encoded hash
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 {
		return false
	}

	// Verify format
	if parts[1] != "argon2id" {
		return false
	}

	// Parse parameters
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Hash the plain password with the same parameters
	otherHash := argon2.IDKey([]byte(plainPassword), salt, iterations, memory, parallelism, uint32(len(hash)))

	// Compare hashes using constant time comparison
	return subtle.ConstantTimeCompare(hash, otherHash) == 1
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}

	bytes, err := generateRandomBytes(uint32(length))
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func HashPassword(password string) (string, error) {
	hasher := NewBcryptHasher(bcrypt.DefaultCost)
	return hasher.HashPassword(password)
}

// ComparePasswords is a convenience function that uses bcrypt
func ComparePasswords(hashedPassword, plainPassword string) bool {
	hasher := NewBcryptHasher(bcrypt.DefaultCost)
	return hasher.ComparePasswords(hashedPassword, plainPassword)
}
