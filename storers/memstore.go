package storers

import (
	"context"
	"errors"
	"sort"
	"time"

	memdb "github.com/hashicorp/go-memdb"

	"lockbox.dev/tokens"
)

var (
	schema = &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"token": &memdb.TableSchema{
				Name: "token",
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "ID", Lowercase: true},
					},
					"profileID": &memdb.IndexSchema{
						Name:    "profileID",
						Unique:  false,
						Indexer: &memdb.StringFieldIndex{Field: "ProfileID", Lowercase: true},
					},
					"clientID": &memdb.IndexSchema{
						Name:    "clientID",
						Unique:  false,
						Indexer: &memdb.StringFieldIndex{Field: "ClientID", Lowercase: true},
					},
				},
			},
		},
	}
)

// Memstore is an in-memory implementation of the Storer interface, for use in testing.
type Memstore struct {
	db *memdb.MemDB
}

// NewMemstore returns an instance of Memstore that is ready to be used as a Storer.
func NewMemstore() (*Memstore, error) {
	db, err := memdb.NewMemDB(schema)
	if err != nil {
		return nil, err
	}
	return &Memstore{
		db: db,
	}, nil
}

// GetToken retrieves the tokens.RefreshToken with an ID matching `token` from the Memstore. If
// no tokens.RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (m *Memstore) GetToken(ctx context.Context, token string) (tokens.RefreshToken, error) {
	txn := m.db.Txn(false)
	tok, err := txn.First("token", "id", token)
	if err != nil {
		return tokens.RefreshToken{}, err
	}
	if tok == nil {
		return tokens.RefreshToken{}, tokens.ErrTokenNotFound
	}
	return *tok.(*tokens.RefreshToken), nil
}

// CreateToken inserts the passed tokens.RefreshToken into the Memstore. If a tokens.RefreshToken with
// the same ID already exists in the Memstore, an ErrTokenAlreadyExists error will be
// returned, and the tokens.RefreshToken will not be inserted.
func (m *Memstore) CreateToken(ctx context.Context, token tokens.RefreshToken) error {
	txn := m.db.Txn(true)
	defer txn.Abort()
	exists, err := txn.First("token", "id", token.ID)
	if err != nil {
		return err
	}
	if exists != nil {
		return tokens.ErrTokenAlreadyExists
	}
	err = txn.Insert("token", &token)
	if err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// UpdateTokens applies `change` to all the tokens.RefreshTokens in the Memstore that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (m *Memstore) UpdateTokens(ctx context.Context, change tokens.RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}

	txn := m.db.Txn(true)
	defer txn.Abort()

	var iter memdb.ResultIterator
	var err error
	if change.ID != "" {
		iter, err = txn.Get("token", "id", change.ID)
	} else if change.ProfileID != "" {
		iter, err = txn.Get("token", "profileID", change.ProfileID)
	} else if change.ClientID != "" {
		iter, err = txn.Get("token", "clientID", change.ClientID)
	} else {
		return errors.New("invalid change; needs an ID, ProfileID, or ClientID")
	}
	if err != nil {
		return err
	}

	for {
		token := iter.Next()
		if token == nil {
			break
		}
		updated := tokens.ApplyChange(*token.(*tokens.RefreshToken), change)
		err = txn.Insert("token", &updated)
		if err != nil {
			return err
		}
	}
	txn.Commit()
	return nil
}

// UseToken marks a tokens.RefreshToken as used, or returns a tokens.ErrTokenUsed
// error if the tokens.RefreshToken was already marked used.
func (m *Memstore) UseToken(ctx context.Context, id string) error {
	txn := m.db.Txn(true)
	defer txn.Abort()

	tok, err := txn.First("token", "id", id)
	if err != nil {
		return err
	}
	if tok == nil {
		return tokens.ErrTokenNotFound
	}

	if tok.(*tokens.RefreshToken).Used {
		return tokens.ErrTokenUsed
	}

	used := true
	updated := tokens.ApplyChange(*tok.(*tokens.RefreshToken), tokens.RefreshTokenChange{
		Used: &used,
	})
	err = txn.Insert("token", &updated)
	if err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// GetTokensByProfileID retrieves up to NumTokenResults tokens.RefreshTokens from the Memstore. Only
// tokens.RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since` is
// non-empty, only tokens.RefreshTokens with a CreatedAt property that is after `since` will be returned.
// If `before` is non-empty, only tokens.RefreshTokens with a CreatedAt property that is before `before`
// will be returned. tokens.RefreshTokens will be sorted by their CreatedAt property, with the most recent
// coming first.
func (m *Memstore) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]tokens.RefreshToken, error) {
	txn := m.db.Txn(false)
	defer txn.Abort()

	var toks []tokens.RefreshToken
	iter, err := txn.Get("token", "profileID", profileID)
	if err != nil {
		return nil, err
	}

	for {
		tok := iter.Next()
		if tok == nil {
			break
		}
		token := *tok.(*tokens.RefreshToken)
		if !before.IsZero() && !token.CreatedAt.Before(before) {
			continue
		}
		if !since.IsZero() && !token.CreatedAt.After(since) {
			continue
		}
		toks = append(toks, token)
	}
	if len(toks) > tokens.NumTokenResults {
		toks = toks[:tokens.NumTokenResults]
	}
	sort.Sort(tokens.RefreshTokensByCreatedAt(toks))
	return toks, nil
}
