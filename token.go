package tokens

//go:generate go-bindata -pkg migrations -o migrations/generated.go sql/

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/apex/log"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pborman/uuid"
	"impractical.co/pqarrays"
)

const (
	// NumTokenResults is the number of Tokens to retrieve when listing Tokens.
	NumTokenResults = 25

	refreshLength = time.Duration(time.Hour * 24 * 14)
)

var (
	// ErrTokenNotFound is returned when a Token is requested but its ID doesn't exist.
	ErrTokenNotFound = errors.New("token not found")
	// ErrInvalidToken is returned when a Token ID and Value are passed to Validate
	// but do not match a valid Token.
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenAlreadyExists is returned when a Token is created, but its ID already exists in the Storer.
	ErrTokenAlreadyExists = errors.New("token already exists")
	// ErrTokenRevoked is returned when the Token identified by Validate has been revoked.
	ErrTokenRevoked = errors.New("token revoked")
	// ErrTokenUsed is returned when the Token identified by Validate has already been used.
	ErrTokenUsed = errors.New("token used")
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

// GetSQLTableName returns the name of the PostgreSQL table RefreshTokens will be stored
// in. It is required for use with pan.
func (t RefreshToken) GetSQLTableName() string {
	return "tokens"
}

// RefreshTokenChange represents a change to one or more RefreshTokens. If ID is set, only the RefreshToken
// specified by that ID will be changed. If ProfileID is set, all Tokens with a matching ProfileID property
// will be changed. If ClientID is set, all Tokens with a matching ClientID property will be changed.
//
// Revoked and Used specify the new values for the RefreshToken(s)' Revoked or Used properties. If nil,
// the property won't be updated.
type RefreshTokenChange struct {
	ID        string
	ProfileID string
	ClientID  string

	Revoked *bool
	Used    *bool
}

// IsEmpty returns true if the RefreshTokenChange would not update any property on the matching RefreshTokens.
func (r RefreshTokenChange) IsEmpty() bool {
	return r.Revoked == nil && r.Used == nil
}

// ApplyChange updates the properties on `t` as specified by `change`. It does not check that `t` would be
// matched by the ID, ProfileID, or ClientID properties of `change`.
func ApplyChange(t RefreshToken, change RefreshTokenChange) RefreshToken {
	result := t
	if change.Revoked != nil {
		result.Revoked = *change.Revoked
	}
	if change.Used != nil {
		result.Used = *change.Used
	}
	return result
}

// Storer represents an interface to a persistence method for RefreshTokens. It is used to store, update, and
// retrieve RefreshTokens.
type Storer interface {
	GetToken(ctx context.Context, id string) (RefreshToken, error)
	CreateToken(ctx context.Context, token RefreshToken) error
	UpdateTokens(ctx context.Context, change RefreshTokenChange) error
	GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error)
}

// FillTokenDefaults returns a copy of `token` with all empty properties that have default values, like ID
// and CreatedAt set to their default values.
func FillTokenDefaults(token RefreshToken) (RefreshToken, error) {
	res := token
	if res.ID == "" {
		res.ID = uuid.NewRandom().String()
	}
	if res.CreatedAt.IsZero() {
		res.CreatedAt = time.Now()
	}
	return res, nil
}

// RefreshTokensByCreatedAt represents a slice of RefreshTokens that can be sorted by their CreatedAt property
// using the sort package.
type RefreshTokensByCreatedAt []RefreshToken

// Less returns true if the RefreshToken at position `i` has a CreatedAt property that is more recent than the
// RefreshToken at position `j`.
func (r RefreshTokensByCreatedAt) Less(i, j int) bool {
	return r[i].CreatedAt.After(r[j].CreatedAt)
}

// Len returns the number of RefreshTokens in the slice.
func (r RefreshTokensByCreatedAt) Len() int {
	return len(r)
}

// Swap puts the RefreshToken in position `i` in position `j`, and the RefreshToken in position `j` in position `i`.
func (r RefreshTokensByCreatedAt) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// Dependencies manages the dependency injection for the tokens package. All its properties are required for
// a Dependencies struct to be valid.
type Dependencies struct {
	Storer        Storer // Storer is the Storer to use when retrieving, setting, or removing RefreshTokens.
	JWTPrivateKey *rsa.PrivateKey
	JWTPublicKey  *rsa.PublicKey
	Log           *log.Logger
}

// Validate checks that the token with the given ID has the given value, and returns an
// ErrInvalidToken if not.
func (d Dependencies) Validate(ctx context.Context, jwtVal string) (RefreshToken, error) {
	tok, err := jwt.Parse(jwtVal, func(token *jwt.Token) (interface{}, error) {
		return d.JWTPublicKey, nil
	})
	if err != nil {
		d.Log.WithError(err).Debug("Error validating token.")
		return RefreshToken{}, ErrInvalidToken
	}
	claims, ok := tok.Claims.(*jwt.StandardClaims)
	if !ok {
		return RefreshToken{}, ErrInvalidToken
	}
	token, err := d.Storer.GetToken(ctx, claims.Id)
	if err == ErrTokenNotFound {
		return RefreshToken{}, ErrInvalidToken
	} else if err != nil {
		return RefreshToken{}, err
	}
	if token.Revoked {
		return RefreshToken{}, ErrTokenRevoked
	}
	if token.Used {
		return RefreshToken{}, ErrTokenUsed
	}
	return token, nil
}

func (d Dependencies) CreateJWT(ctx context.Context, token RefreshToken) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Audience:  token.ClientID,
		ExpiresAt: token.CreatedAt.UTC().Add(refreshLength).Unix(),
		Id:        token.ID,
		IssuedAt:  token.CreatedAt.UTC().Unix(),
		Issuer:    token.CreatedFrom,
		NotBefore: token.CreatedAt.UTC().Add(-1 * time.Hour).Unix(),
		Subject:   token.ProfileID,
	}).SignedString(d.JWTPrivateKey)
}
