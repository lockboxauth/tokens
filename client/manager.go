package tokensClient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"code.secondbit.org/uuid.hg"
	"golang.org/x/net/context"
)

var (
	// ErrTokenNotFound is returned when a Token was requested but could not be found.
	ErrTokenNotFound = errors.New("token not found")
)

// Token is a representation of a RefreshToken obtained from the API.
type Token struct {
	ID          string   `json:"id"`
	CreatedFrom string   `json:"createdFrom"`
	Scopes      []string `json:"scopes"`
	ProfileID   uuid.ID  `json:"profileID"`
	ClientID    uuid.ID  `json:"clientID"`
	Revoked     bool     `json:"revoked"`
	Used        bool     `json:"used"`
}

// IsValid returns true if the Token is still considered valid and usable.
func IsValid(t Token) bool {
	return t.Revoked == false && t.Used == false
}

// Manager encompasses the possible actions to take on Tokens. It defines how clients
// will interact with the API.
type Manager interface {
	Get(ctx context.Context, token string) (Token, error)
	Insert(ctx context.Context, token Token) (string, error)
	Revoke(ctx context.Context, token string) error
	Use(ctx context.Context, token string) error
}

// MemoryManager is an in-memory implementation of the Manager interface, for use in testing.
type MemoryManager struct {
	tokens map[string]Token
	lock   sync.RWMutex
}

// NewMemoryManager returns a ready-to-use MemoryManager that can be leveraged as a Manager.
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		tokens: map[string]Token{},
	}
}

// Get retrieves the Token specified by the ID passed in. If no Token matches that ID, an
// ErrTokenNotFound is returned.
func (m *MemoryManager) Get(ctx context.Context, token string) (Token, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	t, ok := m.tokens[token]
	if !ok {
		return Token{}, ErrTokenNotFound
	}
	return t, nil
}

// Insert creates the passed Token in the tokens service. The string returned is the ID
// of the inserted Token.
func (m *MemoryManager) Insert(ctx context.Context, token Token) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	token.ID = hex.EncodeToString(b)

	m.lock.Lock()
	defer m.lock.Unlock()
	m.tokens[token.ID] = token

	return token.ID, nil
}

// Revoke marks the Token associated with the passed ID as revoked, probably for security
// reasons. If no Token matches the ID provided, ErrTokenNotFound is returned.
func (m *MemoryManager) Revoke(ctx context.Context, token string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	t, ok := m.tokens[token]
	if !ok {
		return ErrTokenNotFound
	}
	t.Revoked = true
	m.tokens[t.ID] = t

	return nil
}

// Use marks the Token associated with the passed ID as used, meaning it can't be used again.
// If no Token matches the passed ID, ErrTokenNotFound is returned.
func (m *MemoryManager) Use(ctx context.Context, token string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	t, ok := m.tokens[token]
	if !ok {
		return ErrTokenNotFound
	}
	t.Used = true
	m.tokens[t.ID] = t

	return nil
}
