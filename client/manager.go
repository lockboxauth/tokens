package tokensClient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"darlinggo.co/hash"
)

var (
	// ErrTokenNotFound is returned when a Token was requested but could not be found.
	ErrTokenNotFound = errors.New("token not found")
)

// Token is a representation of a RefreshToken obtained from the API.
type Token struct {
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	CreatedAt   string   `json:"createdAt"`
	CreatedFrom string   `json:"createdFrom"`
	Scopes      []string `json:"scopes"`
	ProfileID   string   `json:"profileID"`
	ClientID    string   `json:"clientID"`
	Revoked     bool     `json:"revoked"`
	Used        bool     `json:"used"`
}

// IsValid returns true if the Token is still considered valid and usable.
func IsValid(t Token) bool {
	return t.Revoked == false && t.Used == false
}

// Build encodes the passed Token into a single string that is easy to pass
// around and store. It should be treated as opaque.
func Build(t Token) string {
	return strings.Join([]string{t.ID, t.Value}, ".")
}

// Break returns the ID and Value properties of the Token that the passed
// string was generated from, or an error if the passed string was not
// correctly generated from a Token.
func Break(val string) (id, value string, err error) {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return "", "", ErrInvalidTokenString
	}
	return parts[0], parts[1], nil
}

// Manager encompasses the possible actions to take on Tokens. It defines how clients
// will interact with the API.
type Manager interface {
	Get(ctx context.Context, id string) (Token, error)
	Validate(ctx context.Context, token string) error
	Insert(ctx context.Context, token Token) (Token, error)
	Revoke(ctx context.Context, id string) error
	Use(ctx context.Context, id string) error
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

// Get retrieves the Token specified by the ID passed in. If no Tokens match that ID, an
// ErrTokenNotFound is returned.
func (m *MemoryManager) Get(ctx context.Context, id string) (Token, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	t, ok := m.tokens[id]
	if !ok {
		return Token{}, ErrTokenNotFound
	}
	return t, nil
}

// Validate checks that the passed string represents a valid Token.
func (m *MemoryManager) Validate(ctx context.Context, token string) error {
	id, value, err := Break(token)
	if err != nil {
		return err
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	t, ok := m.tokens[id]
	if !ok {
		return ErrInvalidTokenString
	}
	if !hash.Compare([]byte(value), []byte(t.Value)) {
		return ErrInvalidTokenString
	}
	return nil
}

// Insert creates the passed Token in the tokens service. The token returned is the what
// the service actually persisted, after it filled any defaults.
func (m *MemoryManager) Insert(ctx context.Context, token Token) (Token, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return Token{}, err
	}
	token.ID = hex.EncodeToString(b)

	m.lock.Lock()
	defer m.lock.Unlock()
	m.tokens[token.ID] = token

	return token, nil
}

// Revoke marks the Token associated with the passed ID as revoked, probably for security
// reasons. If no Token matches the ID provided, ErrTokenNotFound is returned.
func (m *MemoryManager) Revoke(ctx context.Context, id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	t, ok := m.tokens[id]
	if !ok {
		return ErrTokenNotFound
	}
	t.Revoked = true
	m.tokens[t.ID] = t

	return nil
}

// Use marks the Token associated with the passed ID as used, meaning it can't be used again.
// If no Token matches the passed ID, ErrTokenNotFound is returned.
func (m *MemoryManager) Use(ctx context.Context, id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	t, ok := m.tokens[id]
	if !ok {
		return ErrTokenNotFound
	}
	t.Used = true
	m.tokens[t.ID] = t

	return nil
}
