package apiv1

import (
	"time"

	"code.impractical.co/tokens"

	"code.impractical.co/pqarrays"
)

// RefreshToken is a representation of the tokens.RefreshToken type. It is
// tooled towards being used in requests and responses for apiv1.
type RefreshToken struct {
	ID          string    `json:"id"`
	Value       string    `json:"value,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	CreatedFrom string    `json:"createdFrom"`
	Scopes      []string  `json:"scopes,omitempty"`
	ProfileID   string    `json:"profileID"`
	ClientID    string    `json:"clientID"`
	Revoked     bool      `json:"revoked"`
	Used        bool      `json:"used"`
}

// RefreshTokenChange is a representation of the tokens.RefreshTokenChange type.
// It is toold towards being used in requests and responses for apiv1.
type RefreshTokenChange struct {
	ID        string
	ProfileID string
	ClientID  string

	Revoked *bool
	Used    *bool
}

func coreToken(token RefreshToken) tokens.RefreshToken {
	return tokens.RefreshToken{
		ID:          token.ID,
		Value:       token.Value,
		CreatedAt:   token.CreatedAt,
		CreatedFrom: token.CreatedFrom,
		Scopes:      pqarrays.StringArray(token.Scopes),
		ProfileID:   token.ProfileID,
		ClientID:    token.ClientID,
		Revoked:     token.Revoked,
		Used:        token.Used,
	}
}

func apiToken(token tokens.RefreshToken) RefreshToken {
	return RefreshToken{
		ID:          token.ID,
		Value:       token.Value,
		CreatedAt:   token.CreatedAt,
		CreatedFrom: token.CreatedFrom,
		Scopes:      []string(token.Scopes),
		ProfileID:   token.ProfileID,
		ClientID:    token.ClientID,
		Revoked:     token.Revoked,
		Used:        token.Used,
	}
}

func coreChange(change RefreshTokenChange) tokens.RefreshTokenChange {
	return tokens.RefreshTokenChange{
		ID:        change.ID,
		ProfileID: change.ProfileID,
		ClientID:  change.ClientID,
		Revoked:   change.Revoked,
		Used:      change.Used,
	}
}

func apiChange(change tokens.RefreshTokenChange) RefreshTokenChange {
	return RefreshTokenChange{
		ID:        change.ID,
		ProfileID: change.ProfileID,
		ClientID:  change.ClientID,
		Revoked:   change.Revoked,
		Used:      change.Used,
	}
}
