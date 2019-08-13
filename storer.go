package tokens

import (
	"context"
	"time"
)

// Storer represents an interface to a persistence method for RefreshTokens. It is used to store, update, and
// retrieve RefreshTokens.
type Storer interface {
	GetToken(ctx context.Context, id string) (RefreshToken, error)
	CreateToken(ctx context.Context, token RefreshToken) error
	UpdateTokens(ctx context.Context, change RefreshTokenChange) error
	UseToken(ctx context.Context, id string) error
	GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error)
}
