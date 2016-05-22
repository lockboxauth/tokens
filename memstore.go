package tokens

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/context"
)

// Memstore is an in-memory implementation of the Storer interface, for use in testing.
type Memstore struct {
	tokens      map[string]RefreshToken
	tokenHashes map[string]struct{}
	lock        sync.RWMutex
}

// NewMemstore returns an instance of Memstore that is ready to be used as a Storer.
func NewMemstore() *Memstore {
	return &Memstore{
		tokens:      map[string]RefreshToken{},
		tokenHashes: map[string]struct{}{},
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
	_, ok = m.tokenHashes[token.Hash+":"+token.HashSalt+":"+strconv.Itoa(token.HashIterations)]
	if ok {
		return ErrTokenHashAlreadyExists
	}
	token.Value = ""
	m.tokens[token.ID] = token
	m.tokenHashes[token.Hash+":"+token.HashSalt+":"+strconv.Itoa(token.HashIterations)] = struct{}{}

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
		if change.ProfileID != "" && change.ProfileID != t.ProfileID {
			continue
		}
		if change.ClientID != "" && change.ClientID != t.ClientID {
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
func (m *Memstore) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	var tokens []RefreshToken

	for _, t := range m.tokens {
		if t.ProfileID != profileID {
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
