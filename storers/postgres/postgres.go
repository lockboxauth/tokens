package postgres

import (
	"context"
	"database/sql"
	"time"

	"darlinggo.co/pan"
	"github.com/lib/pq"

	"lockbox.dev/tokens"
)

//go:generate go-bindata -pkg migrations -o migrations/generated.go sql/

const (
	TestConnStringEnvVar = "PG_TEST_DB"
)

// Storer is an implementation of the Storer interface that is production quality
// and backed by a PostgreSQL database.
type Storer struct {
	db *sql.DB
}

// NewStorer returns an instance of Storer that is ready to be used as a Storer.
func NewStorer(ctx context.Context, db *sql.DB) Storer {
	return Storer{db: db}
}

func getTokenSQL(ctx context.Context, token string) *pan.Query {
	var t RefreshToken
	query := pan.New("SELECT " + pan.Columns(t).String() + " FROM " + pan.Table(t))
	query.Where()
	query.Comparison(t, "ID", "=", token)
	return query.Flush(" ")
}

// GetToken retrieves the tokens.RefreshToken with an ID matching `token` from Storer. If no
// tokens.RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (s Storer) GetToken(ctx context.Context, token string) (tokens.RefreshToken, error) {
	query := getTokenSQL(ctx, token)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return tokens.RefreshToken{}, err
	}
	rows, err := s.db.Query(queryStr, query.Args()...)
	if err != nil {
		return tokens.RefreshToken{}, err
	}
	var t RefreshToken
	var found bool
	for rows.Next() {
		err := pan.Unmarshal(rows, &t)
		if err != nil {
			return tokens.RefreshToken{}, err
		}
		found = true
	}
	if err = rows.Err(); err != nil {
		return tokens.RefreshToken{}, err
	}
	if !found {
		return tokens.RefreshToken{}, tokens.ErrTokenNotFound
	}
	return fromPostgres(t), nil
}

func createTokenSQL(token tokens.RefreshToken) *pan.Query {
	query := pan.Insert(toPostgres(token))
	return query.Flush(" ")
}

// CreateToken inserts the passed tokens.RefreshToken into Storer. If a tokens.RefreshToken
// with the same ID already exists in Storer, an ErrTokenAlreadyExists error
// will be returned, and the tokens.RefreshToken will not be inserted.
func (s Storer) CreateToken(ctx context.Context, token tokens.RefreshToken) error {
	query := createTokenSQL(token)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(queryStr, query.Args()...)
	if e, ok := err.(*pq.Error); ok {
		if e.Constraint == "tokens_pkey" {
			err = tokens.ErrTokenAlreadyExists
		}
	}
	return err
}

func updateTokensSQL(ctx context.Context, change tokens.RefreshTokenChange) *pan.Query {
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

// UpdateTokens applies `change` to all the tokens.RefreshTokens in Storer that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (s Storer) UpdateTokens(ctx context.Context, change tokens.RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	if !change.HasFilter() {
		return tokens.ErrNoTokenChangeFilter
	}
	query := updateTokensSQL(ctx, change)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(queryStr, query.Args()...)
	return err
}

func useTokenSQL(ctx context.Context, id string) *pan.Query {
	var t RefreshToken
	query := pan.New("UPDATE " + pan.Table(t) + " SET ")
	query.Comparison(t, "Used", "=", true)
	query.Flush(" ").Where()
	query.Comparison(t, "ID", "=", id)
	query.Comparison(t, "Used", "=", false)
	return query.Flush(" AND ")
}

func useTokenExistsSQL(ctx context.Context, id string) *pan.Query {
	var t RefreshToken
	query := pan.New("SELECT COUNT(*) FROM " + pan.Table(t))
	query.Where()
	query.Comparison(t, "ID", "=", id)
	query.Comparison(t, "Used", "=", true)
	return query.Flush(" AND ")
}

// UseToken atomically marks the token specified by `id` as used, returning a
// tokens.ErrTokenUsed if the token has already been marked used, or a
// tokens.ErrTokenNotFound if the token doesn't exist in Storer.
func (s Storer) UseToken(ctx context.Context, id string) error {
	query := useTokenSQL(ctx, id)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return err
	}
	rows, err := s.db.Exec(queryStr, query.Args()...)
	if err != nil {
		return err
	}
	results, err := rows.RowsAffected()
	if err != nil {
		return err
	}
	if results >= 1 {
		return nil
	}
	query = useTokenExistsSQL(ctx, id)
	queryStr, err = query.PostgreSQLString()
	if err != nil {
		return err
	}
	err = s.db.QueryRow(queryStr, query.Args()...).Scan(&results)
	if err != nil {
		return err
	}
	if results >= 1 {
		return tokens.ErrTokenUsed
	}
	return tokens.ErrTokenNotFound
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
	query.Limit(tokens.NumTokenResults)
	return query.Flush(" ")
}

// GetTokensByProfileID retrieves up to NumTokenResults tokens.RefreshTokens from Storer. Only
// tokens.RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since`
// is non-empty, only tokens.RefreshTokens with a CreatedAt property that is after `since` will be
// returned. If `before` is non-empty, only tokens.RefreshTokens with a CreatedAt property that is
// before `before` will be returned. tokens.RefreshTokens will be sorted by their CreatedAt property,
// with the most recent coming first.
func (s Storer) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]tokens.RefreshToken, error) {
	query := getTokensByProfileIDSQL(ctx, profileID, since, before)
	queryStr, err := query.PostgreSQLString()
	if err != nil {
		return []tokens.RefreshToken{}, err
	}
	rows, err := s.db.Query(queryStr, query.Args()...)
	if err != nil {
		return []tokens.RefreshToken{}, err
	}
	var toks []tokens.RefreshToken
	for rows.Next() {
		var token RefreshToken
		err = pan.Unmarshal(rows, &token)
		if err != nil {
			return toks, err
		}
		toks = append(toks, fromPostgres(token))
	}
	if err = rows.Err(); err != nil {
		return toks, err
	}
	return toks, nil
}
