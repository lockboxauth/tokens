package storers

import (
	"time"

	"impractical.co/auth/tokens"
	"impractical.co/pqarrays"
)

type datastoreTokenUse struct {
	TokenID   string `datastore:"-"`
	Timestamp time.Time
	IsUse     bool
	IsRevoke  bool
	Value     bool
}

type datastoreToken struct {
	ID          string `datastore:"-"`
	CreatedAt   time.Time
	CreatedFrom string
	Scopes      []string
	ProfileID   string
	ClientID    string
}

func fromDatastore(t datastoreToken) tokens.RefreshToken {
	return tokens.RefreshToken{
		ID:          t.ID,
		CreatedAt:   t.CreatedAt,
		CreatedFrom: t.CreatedFrom,
		Scopes:      pqarrays.StringArray(t.Scopes),
		ProfileID:   t.ProfileID,
		ClientID:    t.ClientID,
	}
}

func toDatastore(t tokens.RefreshToken) datastoreToken {
	return datastoreToken{
		ID:          t.ID,
		CreatedAt:   t.CreatedAt,
		CreatedFrom: t.CreatedFrom,
		Scopes:      []string(t.Scopes),
		ProfileID:   t.ProfileID,
		ClientID:    t.ClientID,
	}
}
