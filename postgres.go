package tokens

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
	"github.com/secondbit/pan"

	"golang.org/x/net/context"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(ctx context.Context, conn string) (Postgres, error) {
	db, err := sql.Open("postgres", conn)
	if err != nil {
		return Postgres{}, err
	}
	return Postgres{db: db}, nil
}

func (t RefreshToken) GetSQLTableName() string {
	return "tokens"
}

func getTokenSQL(ctx context.Context, token string) *pan.Query {
	var t RefreshToken
	fields, _ := pan.GetFields(t)
	query := pan.New(pan.POSTGRES, "SELECT "+pan.QueryList(fields)+" FROM "+pan.GetTableName(t))
	query.IncludeWhere()
	query.Include(pan.GetUnquotedColumn(t, "ID")+" = ?", token)
	return query.FlushExpressions(" ")
}

func (p Postgres) GetToken(ctx context.Context, token string) (RefreshToken, error) {
	query := getTokenSQL(ctx, token)
	rows, err := p.db.Query(query.String(), query.Args...)
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
	fields, values := pan.GetFields(token)
	query := pan.New(pan.POSTGRES, "INSERT INTO "+pan.GetTableName(token))
	query.Include("(" + pan.QueryList(fields) + ")")
	query.Include("VALUES")
	query.Include("("+pan.VariableList(len(values))+")", values...)
	return query.FlushExpressions(" ")
}

func (p Postgres) CreateToken(ctx context.Context, token RefreshToken) error {
	query := createTokenSQL(token)
	_, err := p.db.Exec(query.String(), query.Args...)
	if e, ok := err.(*pq.Error); ok && e.Constraint == "tokens_pkey" {
		err = ErrTokenAlreadyExists
	}
	return err
}

func updateTokensSQL(ctx context.Context, change RefreshTokenChange) *pan.Query {
	var t RefreshToken
	query := pan.New(pan.POSTGRES, "UPDATE "+pan.GetTableName(t)+" SET ")
	query.IncludeIfNotNil(pan.GetUnquotedColumn(t, "Revoked")+" = ?", change.Revoked)
	query.IncludeIfNotNil(pan.GetUnquotedColumn(t, "Used")+" = ?", change.Used)
	query.FlushExpressions(", ")
	query.IncludeWhere()
	query.IncludeIfNotEmpty(pan.GetUnquotedColumn(t, "ID")+" = ?", change.ID)
	query.IncludeIfNotNil(pan.GetUnquotedColumn(t, "ClientID")+" = ?", change.ClientID)
	query.IncludeIfNotNil(pan.GetUnquotedColumn(t, "ProfileID")+" = ?", change.ProfileID)
	return query.FlushExpressions(" AND ")
}

func (p Postgres) UpdateTokens(ctx context.Context, change RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	query := updateTokensSQL(ctx, change)
	_, err := p.db.Exec(query.String(), query.Args...)
	return err
}

func getTokensByProfileIDSQL(ctx context.Context, profileID string, since, before time.Time) *pan.Query {
	var t RefreshToken
	fields, _ := pan.GetFields(t)
	query := pan.New(pan.POSTGRES, "SELECT "+pan.QueryList(fields)+" FROM "+pan.GetTableName(t))
	query.IncludeWhere()
	query.Include(pan.GetUnquotedColumn(t, "ProfileID")+" = ?", profileID)
	query.IncludeIfNotEmpty(pan.GetUnquotedColumn(t, "CreatedAt")+" < ?", before)
	query.IncludeIfNotEmpty(pan.GetUnquotedColumn(t, "CreatedAt")+" > ?", since)
	query.FlushExpressions(" AND ")
	query.Include("ORDER BY " + pan.GetUnquotedColumn(t, "CreatedAt") + " DESC")
	query.IncludeLimit(NumTokenResults)
	return query.FlushExpressions(" ")
}

func (p Postgres) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error) {
	query := getTokensByProfileIDSQL(ctx, profileID, since, before)
	rows, err := p.db.Query(query.String(), query.Args...)
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
