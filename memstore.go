package tokens

import (
	"sort"
	"sync"
	"time"

	"code.secondbit.org/uuid.hg"

	"golang.org/x/net/context"
)

// Memstore is an in-memory implementation of the Storer interface, for use in testing.
type Memstore struct {
	tokens map[string]RefreshToken
	lock   sync.RWMutex
}

// NewMemstore returns an instance of Memstore that is ready to be used as a Storer.
func NewMemstore() *Memstore {
	return &Memstore{
		tokens: map[string]RefreshToken{},
	}
}

// GetToken retrieves the RefreshToken with an ID matching `token` from the Memstore. If
// no RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (m *Memstore) GetToken(ctx context.Context, token string) (RefreshToken, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	result, ok := m.tokens[token]
	if !ok {
		return RefreshToken{}, ErrTokenNotFound
	}
	return result, nil
}

// CreateToken inserts the passed RefreshToken into the Memstore. If a RefreshToken with
// the same ID already exists in the Memstore, an ErrTokenAlreadyExists error will be
// returned, and the RefreshToken will not be inserted.
func (m *Memstore) CreateToken(ctx context.Context, token RefreshToken) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, ok := m.tokens[token.ID]
	if ok {
		return ErrTokenAlreadyExists
	}
	m.tokens[token.ID] = token

	return nil
}

// UpdateTokens applies `change` to all the RefreshTokens in the Memstore that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (m *Memstore) UpdateTokens(ctx context.Context, change RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	for val, t := range m.tokens {
		if change.ID != "" && change.ID != val {
			continue
		}
		if !change.ProfileID.IsZero() && !change.ProfileID.Equal(t.ProfileID) {
			continue
		}
		if !change.ClientID.IsZero() && !change.ClientID.Equal(t.ClientID) {
			continue
		}
		t = ApplyChange(t, change)
		m.tokens[val] = t
	}
	return nil
}

// GetTokensByProfileID retrieves up to NumTokenResults RefreshTokens from the Memstore. Only
// RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since` is
// non-empty, only RefreshTokens with a CreatedAt property that is after `since` will be returned.
// If `before` is non-empty, only RefreshTokens with a CreatedAt property that is before `before`
// will be returned. RefreshTokens will be sorted by their CreatedAt property, with the most recent
// coming first.
func (m *Memstore) GetTokensByProfileID(ctx context.Context, profileID uuid.ID, since, before time.Time) ([]RefreshToken, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	var tokens []RefreshToken

	for _, t := range m.tokens {
		if !t.ProfileID.Equal(profileID) {
			continue
		}
		if !before.IsZero() && !t.CreatedAt.Before(before) {
			continue
		}
		if !since.IsZero() && !t.CreatedAt.After(since) {
			continue
		}
		tokens = append(tokens, t)
	}
	if len(tokens) > NumTokenResults {
		tokens = tokens[:NumTokenResults]
	}
	sort.Sort(RefreshTokensByCreatedAt(tokens))
	return tokens, nil
}
