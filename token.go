package tokens

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	uuid "github.com/hashicorp/go-uuid"
	"golang.org/x/crypto/ssh"
	yall "yall.in"
)

const (
	// NumTokenResults is the number of Tokens to retrieve when listing Tokens.
	NumTokenResults = 25

	refreshLength = time.Hour * 24 * 14
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
	// ErrNoTokenChangeFilter is returned when a TokenChange is passed to UpdateTokens
	// that has none of the filtering fields set.
	ErrNoTokenChangeFilter = errors.New("invalid token change: must have one or more filter fields set")
	// ErrUnexpectedSigningMethod is returned when validating a token that
	// claims to have been signed with a unrecognized signing method.
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	// ErrUnknownSigningKey is returned when validating a token that claims
	// to have been signed with an unrecognized signing key.
	ErrUnknownSigningKey = errors.New("unknown signing key")
)

// RefreshToken represents a refresh token that can be used to obtain a new access token.
type RefreshToken struct {
	ID          string
	CreatedAt   time.Time
	CreatedFrom string
	Scopes      []string
	AccountID   string
	ProfileID   string
	ClientID    string
	Revoked     bool
	Used        bool
}

// RefreshTokenChange represents a change to one or more RefreshTokens. If ID is set, only the RefreshToken
// specified by that ID will be changed. If ProfileID is set, all Tokens with a matching ProfileID property
// will be changed. If ClientID is set, all Tokens with a matching ClientID property will be changed.
//
// Revoked and Used specify the new values for the RefreshToken(s)' Revoked or Used properties. If nil,
// the property won't be updated.
type RefreshTokenChange struct {
	ID        string
	AccountID string
	ProfileID string
	ClientID  string

	Revoked *bool
	Used    *bool
}

// IsEmpty returns true if the RefreshTokenChange would not update any property on the matching RefreshTokens.
func (r RefreshTokenChange) IsEmpty() bool {
	return r.Revoked == nil && r.Used == nil
}

// HasFilter returns true if one of the fields of `r` that is used to filter which tokens to apply the change
// to is set.
func (r RefreshTokenChange) HasFilter() bool {
	if r.ID != "" {
		return true
	}
	if r.ProfileID != "" {
		return true
	}
	if r.ClientID != "" {
		return true
	}
	if r.AccountID != "" {
		return true
	}
	return false
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

// FillTokenDefaults returns a copy of `token` with all empty properties that have default values, like ID
// and CreatedAt set to their default values.
func FillTokenDefaults(token RefreshToken) (RefreshToken, error) {
	res := token
	if res.ID == "" {
		id, err := uuid.GenerateUUID()
		if err != nil {
			return RefreshToken{}, err
		}
		res.ID = id
	}
	if res.CreatedAt.IsZero() {
		res.CreatedAt = time.Now()
	}
	return res, nil
}

// Dependencies manages the dependency injection for the tokens package. All its properties are required for
// a Dependencies struct to be valid.
type Dependencies struct {
	Storer        Storer // Storer is the Storer to use when retrieving, setting, or removing RefreshTokens.
	JWTPrivateKey *rsa.PrivateKey
	JWTPublicKey  *rsa.PublicKey
	ServiceID     string
}

func getPublicKeyFingerprint(pk *rsa.PublicKey) (string, error) {
	p, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("Error creating SSH public key: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(p)
	return fingerprint, nil
}

// Validate checks that the token with the given ID has the given value, and returns an
// ErrInvalidToken if not.
func (d Dependencies) Validate(ctx context.Context, jwtVal string) (RefreshToken, error) {
	tok, err := jwt.Parse(jwtVal, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
		if err != nil {
			return nil, err
		}
		if fp != token.Header["kid"] {
			return nil, fmt.Errorf("%w: %v", ErrUnknownSigningKey, token.Header["kid"])
		}
		return d.JWTPublicKey, nil
	})
	if err != nil {
		yall.FromContext(ctx).WithError(err).Debug("Error validating token.")
		return RefreshToken{}, ErrInvalidToken
	}
	claims, ok := tok.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return RefreshToken{}, ErrInvalidToken
	}
	log := yall.FromContext(ctx).WithField("id", claims.ID)
	token, err := d.Storer.GetToken(ctx, claims.ID)
	if errors.Is(err, ErrTokenNotFound) {
		return RefreshToken{}, ErrInvalidToken
	} else if err != nil {
		log.WithError(err).Error("error retrieving token")
		return RefreshToken{}, err
	}
	if token.Revoked {
		log.Debug("revoked token presented")
		return RefreshToken{}, ErrTokenRevoked
	}
	if token.Used {
		log.Debug("used token presented")
		return RefreshToken{}, ErrTokenUsed
	}
	return token, nil
}

// CreateJWT returns a signed JWT for `token`, using the private key set in
// `d.JWTPrivateKey` as the private key to sign with.
func (d Dependencies) CreateJWT(_ context.Context, token RefreshToken) (string, error) {
	res := jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{token.ClientID},
		ExpiresAt: jwt.NewNumericDate(token.CreatedAt.UTC().Add(refreshLength)),
		ID:        token.ID,
		IssuedAt:  jwt.NewNumericDate(token.CreatedAt.UTC()),
		Issuer:    d.ServiceID,
		NotBefore: jwt.NewNumericDate(token.CreatedAt.UTC().Add(-1 * time.Hour)),
		Subject:   token.ProfileID,
	})
	fp, err := getPublicKeyFingerprint(d.JWTPublicKey)
	if err != nil {
		return "", err
	}
	res.Header["kid"] = fp
	return res.SignedString(d.JWTPrivateKey)
}
