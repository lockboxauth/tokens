package tokens

import (
	"context"
	"database/sql"
	"time"

	"darlinggo.co/pan"

	"github.com/lib/pq"
)

// Postgres is an implementation of the Storer interface that is production quality
// and backed by a PostgreSQL database.
type Postgres struct {
	db *sql.DB
}

// NewPostgres returns an instance of Postgres that is ready to be used as a Storer.
func NewPostgres(ctx context.Context, db *sql.DB) (Postgres, error) {
	return Postgres{db: db}, nil
}

// GetSQLTableName returns the name of the PostgreSQL table RefreshTokens will be stored
// in. It is required for use with pan.
func (t RefreshToken) GetSQLTableName() string {
	return "tokens"
}

func getTokenSQL(ctx context.Context, token string) *pan.Query {
	var t RefreshToken
	query := pan.New("SELECT " + pan.Columns(t).String() + " FROM " + pan.Table(t))
	query.Where()
	query.Comparison(t, "ID", "=", token)
	return query.Flush(" ")
}

// GetToken retrieves the RefreshToken with an ID matching `token` from Postgres. If no
// RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (p Postgres) GetToken(ctx context.Context, token string) (RefreshToken, error) {
	query := getTokenSQL(ctx, token)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return RefreshToken{}, err
	}
	rows, err := p.db.Query(queryStr, query.Args()...)
	if err != nil {
		return RefreshToken{}, err
	}
	var t RefreshToken
	var found bool
	for rows.Next() {
		err := pan.Unmarshal(rows, &t)
		if err != nil {
			return t, err
		}
		found = true
	}
	if err = rows.Err(); err != nil {
		return t, err
	}
	if !found {
		return t, ErrTokenNotFound
	}
	return t, nil
}

func createTokenSQL(token RefreshToken) *pan.Query {
	query := pan.Insert(token)
	return query.Flush(" ")
}

// CreateToken inserts the passed RefreshToken into Postgres. If a RefreshToken
// with the same ID already exists in Postgres, an ErrTokenAlreadyExists error
// will be returned, and the RefreshToken will not be inserted.
func (p Postgres) CreateToken(ctx context.Context, token RefreshToken) error {
	query := createTokenSQL(token)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return err
	}
	_, err = p.db.Exec(queryStr, query.Args()...)
	if e, ok := err.(*pq.Error); ok {
		if e.Constraint == "tokens_pkey" {
			err = ErrTokenAlreadyExists
		}
	}
	return err
}

func updateTokensSQL(ctx context.Context, change RefreshTokenChange) *pan.Query {
	var t RefreshToken
	query := pan.New("UPDATE " + pan.Table(t) + " SET ")
	if change.Revoked != nil {
		query.Comparison(t, "Revoked", "=", change.Revoked)
	}
	if change.Used != nil {
		query.Comparison(t, "Used", "=", change.Used)
	}
	query.Flush(", ").Where()
	if change.ID != "" {
		query.Comparison(t, "ID", "=", change.ID)
	}
	if change.ClientID != "" {
		query.Comparison(t, "ClientID", "=", change.ClientID)
	}
	if change.ProfileID != "" {
		query.Comparison(t, "ProfileID", "=", change.ProfileID)
	}
	return query.Flush(" AND ")
}

// UpdateTokens applies `change` to all the RefreshTokens in Postgres that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (p Postgres) UpdateTokens(ctx context.Context, change RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	query := updateTokensSQL(ctx, change)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return err
	}
	_, err = p.db.Exec(queryStr, query.Args()...)
	return err
}

func getTokensByProfileIDSQL(ctx context.Context, profileID string, since, before time.Time) *pan.Query {
	var t RefreshToken
	query := pan.New("SELECT " + pan.Columns(t).String() + " FROM " + pan.Table(t))
	query.Where()
	query.Comparison(t, "ProfileID", "=", profileID)
	if !before.IsZero() {
		query.Comparison(t, "CreatedAt", "<", before)
	}
	if !since.IsZero() {
		query.Comparison(t, "CreatedAt", ">", since)
	}
	query.Flush(" AND ")
	query.OrderByDesc(pan.Column(t, "CreatedAt"))
	query.Limit(NumTokenResults)
	return query.Flush(" ")
}

// GetTokensByProfileID retrieves up to NumTokenResults RefreshTokens from Postgres. Only
// RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since`
// is non-empty, only RefreshTokens with a CreatedAt property that is after `since` will be
// returned. If `before` is non-empty, only RefreshTokens with a CreatedAt property that is
// before `before` will be returned. RefreshTokens will be sorted by their CreatedAt property,
// with the most recent coming first.
func (p Postgres) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error) {
	query := getTokensByProfileIDSQL(ctx, profileID, since, before)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return []RefreshToken{}, err
	}
	rows, err := p.db.Query(queryStr, query.Args()...)
	if err != nil {
		return []RefreshToken{}, err
	}
	var tokens []RefreshToken
	for rows.Next() {
		var token RefreshToken
		err = pan.Unmarshal(rows, &token)
		if err != nil {
			return tokens, err
		}
		tokens = append(tokens, token)
	}
	if err = rows.Err(); err != nil {
		return tokens, err
	}
	return tokens, nil
}
