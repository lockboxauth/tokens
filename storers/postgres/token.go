package postgres

import (
	"time"

	"impractical.co/pqarrays"

	"lockbox.dev/tokens"
)

// RefreshToken represents a refresh token that can be used to obtain a new access token.
type RefreshToken struct {
	ID          string
	CreatedAt   time.Time
	CreatedFrom string
	Scopes      pqarrays.StringArray
	ProfileID   string
	ClientID    string
	AccountID   string
	Revoked     bool
	Used        bool
}

func fromPostgres(token RefreshToken) tokens.RefreshToken {
	return tokens.RefreshToken{
		ID:          token.ID,
		CreatedAt:   token.CreatedAt,
		CreatedFrom: token.CreatedFrom,
		Scopes:      []string(token.Scopes),
		ProfileID:   token.ProfileID,
		ClientID:    token.ClientID,
		AccountID:   token.AccountID,
		Revoked:     token.Revoked,
		Used:        token.Used,
	}
}

func toPostgres(token tokens.RefreshToken) RefreshToken {
	return RefreshToken{
		ID:          token.ID,
		CreatedAt:   token.CreatedAt,
		CreatedFrom: token.CreatedFrom,
		Scopes:      pqarrays.StringArray(token.Scopes),
		ProfileID:   token.ProfileID,
		ClientID:    token.ClientID,
		AccountID:   token.AccountID,
		Revoked:     token.Revoked,
		Used:        token.Used,
	}
}

// GetSQLTableName returns the name of the PostgreSQL table RefreshTokens will be stored
// in. It is required for use with pan.
func (RefreshToken) GetSQLTableName() string {
	return "tokens"
}
