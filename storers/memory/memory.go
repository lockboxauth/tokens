package memory

import (
	"context"
	"fmt"
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
					"accountID": &memdb.IndexSchema{
						Name:    "accountID",
						Unique:  false,
						Indexer: &memdb.StringFieldIndex{Field: "AccountID", Lowercase: true},
					},
				},
			},
		},
	}
)

// Storer is an in-memory implementation of the Storer interface, for use in testing.
type Storer struct {
	db *memdb.MemDB
}

// NewStorer returns an instance of Storer that is ready to be used as a Storer.
func NewStorer() (*Storer, error) {
	db, err := memdb.NewMemDB(schema)
	if err != nil {
		return nil, err
	}
	return &Storer{
		db: db,
	}, nil
}

// GetToken retrieves the tokens.RefreshToken with an ID matching `token` from the Storer. If
// no tokens.RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (m *Storer) GetToken(_ context.Context, token string) (tokens.RefreshToken, error) {
	txn := m.db.Txn(false)
	tok, err := txn.First("token", "id", token)
	if err != nil {
		return tokens.RefreshToken{}, err
	}
	if tok == nil {
		return tokens.RefreshToken{}, tokens.ErrTokenNotFound
	}
	res, ok := tok.(*tokens.RefreshToken)
	if !ok || res == nil {
		return tokens.RefreshToken{}, fmt.Errorf("unexpected response type %T", tok) //nolint:goerr113 // error is logged, not handled
	}
	return *res, nil
}

// CreateToken inserts the passed tokens.RefreshToken into the Storer. If a tokens.RefreshToken with
// the same ID already exists in the Storer, an ErrTokenAlreadyExists error will be
// returned, and the tokens.RefreshToken will not be inserted.
func (m *Storer) CreateToken(_ context.Context, token tokens.RefreshToken) error {
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

// UpdateTokens applies `change` to all the tokens.RefreshTokens in the Storer that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (m *Storer) UpdateTokens(_ context.Context, change tokens.RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}

	if !change.HasFilter() {
		return tokens.ErrNoTokenChangeFilter
	}

	txn := m.db.Txn(true)
	defer txn.Abort()

	var iter memdb.ResultIterator
	var err error
	if change.ID != "" && change.ProfileID == "" && change.ClientID == "" && change.AccountID == "" {
		iter, err = txn.Get("token", "id", change.ID)
	} else if change.ProfileID != "" && change.ClientID == "" && change.ID == "" && change.AccountID == "" {
		iter, err = txn.Get("token", "profileID", change.ProfileID)
	} else if change.ClientID != "" && change.ProfileID == "" && change.ID == "" && change.AccountID == "" {
		iter, err = txn.Get("token", "clientID", change.ClientID)
	} else if change.AccountID != "" && change.ProfileID == "" && change.ID == "" && change.ClientID == "" {
		iter, err = txn.Get("token", "accountID", change.AccountID)
	} else {
		iter, err = txn.Get("token", "id")
	}
	if err != nil {
		return err
	}

	for {
		token := iter.Next()
		if token == nil {
			break
		}
		tok, ok := token.(*tokens.RefreshToken)
		if !ok || tok == nil {
			return fmt.Errorf("unexpected response type %T", tok) //nolint:goerr113 // error is logged, not handled
		}
		if change.ID != "" && tok.ID != change.ID {
			continue
		}
		if change.ProfileID != "" && tok.ProfileID != change.ProfileID {
			continue
		}
		if change.ClientID != "" && tok.ClientID != change.ClientID {
			continue
		}
		if change.AccountID != "" && tok.AccountID != change.AccountID {
			continue
		}
		updated := tokens.ApplyChange(*tok, change)
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
func (m *Storer) UseToken(_ context.Context, id string) error {
	txn := m.db.Txn(true)
	defer txn.Abort()

	tok, err := txn.First("token", "id", id)
	if err != nil {
		return err
	}
	if tok == nil {
		return tokens.ErrTokenNotFound
	}
	found, ok := tok.(*tokens.RefreshToken)
	if !ok || found == nil {
		return fmt.Errorf("unexpected response type %T", tok) //nolint:goerr113 // error is logged, not handled
	}

	if found.Used {
		return tokens.ErrTokenUsed
	}

	used := true
	updated := tokens.ApplyChange(*found, tokens.RefreshTokenChange{
		Used: &used,
	})
	err = txn.Insert("token", &updated)
	if err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// GetTokensByProfileID retrieves up to NumTokenResults tokens.RefreshTokens from the Storer. Only
// tokens.RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since` is
// non-empty, only tokens.RefreshTokens with a CreatedAt property that is after `since` will be returned.
// If `before` is non-empty, only tokens.RefreshTokens with a CreatedAt property that is before `before`
// will be returned. tokens.RefreshTokens will be sorted by their CreatedAt property, with the most recent
// coming first.
func (m *Storer) GetTokensByProfileID(_ context.Context, profileID string, since, before time.Time) ([]tokens.RefreshToken, error) {
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
		token, ok := tok.(*tokens.RefreshToken)
		if !ok || token == nil {
			return nil, fmt.Errorf("unexpected response type %T", tok) //nolint:goerr113 // error is logged, not handled
		}
		if !before.IsZero() && !token.CreatedAt.Before(before) {
			continue
		}
		if !since.IsZero() && !token.CreatedAt.After(since) {
			continue
		}
		toks = append(toks, *token)
	}
	sort.Slice(toks, func(i, j int) bool { return toks[i].CreatedAt.After(toks[j].CreatedAt) })
	if len(toks) > tokens.NumTokenResults {
		toks = toks[:tokens.NumTokenResults]
	}
	return toks, nil
}
