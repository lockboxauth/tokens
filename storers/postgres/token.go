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
	Revoked     bool
	Used        bool
}

func fromPostgres(t RefreshToken) tokens.RefreshToken {
	return tokens.RefreshToken{
		ID:          t.ID,
		CreatedAt:   t.CreatedAt,
		CreatedFrom: t.CreatedFrom,
		Scopes:      []string(t.Scopes),
		ProfileID:   t.ProfileID,
		ClientID:    t.ClientID,
		Revoked:     t.Revoked,
		Used:        t.Used,
	}
}

func toPostgres(t tokens.RefreshToken) RefreshToken {
	return RefreshToken{
		ID:          t.ID,
		CreatedAt:   t.CreatedAt,
		CreatedFrom: t.CreatedFrom,
		Scopes:      pqarrays.StringArray(t.Scopes),
		ProfileID:   t.ProfileID,
		ClientID:    t.ClientID,
		Revoked:     t.Revoked,
		Used:        t.Used,
	}
}

// GetSQLTableName returns the name of the PostgreSQL table RefreshTokens will be stored
// in. It is required for use with pan.
func (t RefreshToken) GetSQLTableName() string {
	return "tokens"
}
