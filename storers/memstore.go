package storers

import (
	"context"
	"sort"
	"sync"
	"time"

	"code.impractical.co/tokens"
)

// Memstore is an in-memory implementation of the Storer interface, for use in testing.
type Memstore struct {
	tokens map[string]tokens.RefreshToken
	lock   sync.RWMutex
}

// NewMemstore returns an instance of Memstore that is ready to be used as a Storer.
func NewMemstore() *Memstore {
	return &Memstore{
		tokens: map[string]tokens.RefreshToken{},
	}
}

// GetToken retrieves the tokens.RefreshToken with an ID matching `token` from the Memstore. If
// no tokens.RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (m *Memstore) GetToken(ctx context.Context, token string) (tokens.RefreshToken, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	result, ok := m.tokens[token]
	if !ok {
		return tokens.RefreshToken{}, tokens.ErrTokenNotFound
	}
	return result, nil
}

// CreateToken inserts the passed tokens.RefreshToken into the Memstore. If a tokens.RefreshToken with
// the same ID already exists in the Memstore, an ErrTokenAlreadyExists error will be
// returned, and the tokens.RefreshToken will not be inserted.
func (m *Memstore) CreateToken(ctx context.Context, token tokens.RefreshToken) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, ok := m.tokens[token.ID]
	if ok {
		return tokens.ErrTokenAlreadyExists
	}
	m.tokens[token.ID] = token

	return nil
}

// UpdateTokens applies `change` to all the tokens.RefreshTokens in the Memstore that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (m *Memstore) UpdateTokens(ctx context.Context, change tokens.RefreshTokenChange) error {
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
		t = tokens.ApplyChange(t, change)
		m.tokens[val] = t
	}
	return nil
}

// GetTokensByProfileID retrieves up to NumTokenResults tokens.RefreshTokens from the Memstore. Only
// tokens.RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since` is
// non-empty, only tokens.RefreshTokens with a CreatedAt property that is after `since` will be returned.
// If `before` is non-empty, only tokens.RefreshTokens with a CreatedAt property that is before `before`
// will be returned. tokens.RefreshTokens will be sorted by their CreatedAt property, with the most recent
// coming first.
func (m *Memstore) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]tokens.RefreshToken, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	var toks []tokens.RefreshToken

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
		toks = append(toks, t)
	}
	if len(toks) > tokens.NumTokenResults {
		toks = toks[:tokens.NumTokenResults]
	}
	sort.Sort(tokens.RefreshTokensByCreatedAt(toks))
	return toks, nil
}
