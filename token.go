package tokens

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/net/context"

	"code.secondbit.org/pqarrays.hg"
)

type storerCtxKeyType struct{}

const (
	// NumTokenResults is the number of Tokens to retrieve when listing Tokens.
	NumTokenResults = 25
)

var (
	// ErrTokenNotFound is returned when a Token is requested but its ID doesn't exist.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenAlreadyExists is returned when a Token is created, but its ID already exists in the Storer.
	ErrTokenAlreadyExists = errors.New("token already exists")

	// ErrStorerKeyEmpty is returned when a context.Context has no value for storerCtxKey.
	ErrStorerKeyEmpty = errors.New("no Storer set in context")
	// ErrStorerKeyNotStorer is returned when the stroerCtxKey value in a context.Context does not fulfill
	// the Storer interface.
	ErrStorerKeyNotStorer = errors.New("value of Storer key in context is not a Storer")

	storerCtxKey = storerCtxKeyType{}
)

// RefreshToken represents a refresh token that can be used to obtain a new access token.
type RefreshToken struct {
	ID          string `datastore:"-"`
	CreatedAt   time.Time
	CreatedFrom string
	Scopes      pqarrays.StringArray
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
	GetToken(ctx context.Context, token string) (RefreshToken, error)
	CreateToken(ctx context.Context, token RefreshToken) error
	UpdateTokens(ctx context.Context, change RefreshTokenChange) error
	GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error)
}

// GenerateTokenID returns a cryptographically random ID for a RefreshToken. If it can't read from the source
// of randomness, it returns an error.
func GenerateTokenID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FillTokenDefaults returns a copy of `token` with all empty properties that have default values, like ID
// and CreatedAt set to their default values.
func FillTokenDefaults(token RefreshToken) (RefreshToken, error) {
	res := token
	if res.ID == "" {
		id, err := GenerateTokenID()
		if err != nil {
			return res, err
		}
		res.ID = id
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

// GetStorer returns a Storer from the passed context.Context. If no Storer is set, an ErrStorerKeyEmpty
// error will be returned. If a Storer is set but does not fill the Storer interface, an ErrStorerKeyNotStorer
// error will be returned.
func GetStorer(ctx context.Context) (Storer, error) {
	val := ctx.Value(storerCtxKey)
	if val == nil {
		return nil, ErrStorerKeyEmpty
	}
	storer, ok := val.(Storer)
	if !ok {
		return nil, ErrStorerKeyNotStorer
	}
	return storer, nil
}

// SetStorer returns a copy of `ctx`, but with its storerCtxKey value set
// to the passed Storer. This Storer can then be retrieved using GetStorer.
func SetStorer(ctx context.Context, storer Storer) context.Context {
	return context.WithValue(ctx, storerCtxKey, storer)
}

// Create inserts `token` into the Storer associated with `ctx`. If a RefreshToken
// with the same ID already exists in the Storer, an ErrTokenAlreadyExists error
// will be returned, and the RefreshToken will not be inserted.
func Create(ctx context.Context, token RefreshToken) error {
	storer, err := GetStorer(ctx)
	if err != nil {
		return err
	}
	err = storer.CreateToken(ctx, token)
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves the RefreshToken with an ID matching `id` from the Storer associated
// with `ctx`. If no RefreshToken has that ID, an ErrTokenNotFound error is returned.
func Get(ctx context.Context, id string) (RefreshToken, error) {
	storer, err := GetStorer(ctx)
	if err != nil {
		return RefreshToken{}, err
	}
	token, err := storer.GetToken(ctx, id)
	if err != nil {
		return RefreshToken{}, err
	}
	return token, nil
}

// Update applies `change` to all the RefreshTokens in the Storer associated with `ctx`
// that match the ID, ProfileID, or ClientID constraints of `change`.
func Update(ctx context.Context, change RefreshTokenChange) error {
	storer, err := GetStorer(ctx)
	if err != nil {
		return err
	}
	err = storer.UpdateTokens(ctx, change)
	if err != nil {
		return err
	}
	return nil
}
