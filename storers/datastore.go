package storers

import (
	"context"
	"time"

	"cloud.google.com/go/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"impractical.co/auth/tokens"
)

const (
	datastoreTokenKind    = "RefreshToken"
	datastoreTokenUseKind = "RefreshTokenUse"
)

// Datastore is an implementation of the Storer interface that is production quality
// and backed by Google Cloud Datastore.
type Datastore struct {
	client    *datastore.Client
	namespace string
}

// NewDatastore returns a Datastore instance that is backed by the specified
// *datastore.Client. The returned Datastore instance is ready to be used as a Storer.
func NewDatastore(ctx context.Context, client *datastore.Client) (*Datastore, error) {
	return &Datastore{client: client}, nil
}

// key returns the datastore key to use for a given ID.
func (d *Datastore) key(id string) *datastore.Key {
	key := datastore.NameKey(datastoreTokenKind, id, nil)
	if d.namespace != "" {
		key.Namespace = d.namespace
	}
	return key
}

// useKey returns the datastore key to use for a given token ID
// when inserting a use/revocation record into the datastore.
func (d *Datastore) useKey(id string) *datastore.Key {
	key := datastore.NameKey(datastoreTokenUseKind, id, nil)
	if d.namespace != "" {
		key.Namespace = d.namespace
	}
	return key
}

// GetToken retrieves the tokens.RefreshToken with an ID matching `id` from the Datastore. If no
// tokens.RefreshToken has that ID, an ErrTokenNotFound error is returned.
func (d *Datastore) GetToken(ctx context.Context, id string) (tokens.RefreshToken, error) {
	var tok datastoreToken
	err := d.client.Get(ctx, d.key(id), &tok)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return tokens.RefreshToken{}, tokens.ErrTokenNotFound
		}
		return tokens.RefreshToken{}, err
	}
	tok.ID = id
	res := fromDatastore(tok)

	// retrieve revocation and use data
	var use datastoreTokenUse
	err = d.client.Get(ctx, d.useKey(id), &use)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return tokens.RefreshToken{}, err
	}
	res.Used = use.IsUse
	res.Revoked = use.IsRevoke
	return res, nil
}

// CreateToken inserts the passed tokens.RefreshToken into the Datastore. If a tokens.RefreshToken
// with the same ID already exists in the Datastore, a tokens.ErrTokenAlreadyExists error
// will be returned, and the tokens.RefreshToken will not be inserted.
func (d *Datastore) CreateToken(ctx context.Context, token tokens.RefreshToken) error {
	tok := toDatastore(token)
	mut := datastore.NewInsert(d.key(tok.ID), &tok)
	_, err := d.client.Mutate(ctx, mut)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return tokens.ErrTokenAlreadyExists
		}
		return err
	}
	if !token.Used && !token.Revoked {
		return nil
	}
	use := datastoreTokenUse{
		Timestamp: time.Now(),
		IsUse:     token.Used,
		IsRevoke:  token.Revoked,
	}
	mut = datastore.NewUpsert(d.useKey(tok.ID), &use)
	_, err = d.client.Mutate(ctx, mut)
	if err != nil {
		return err
	}
	return nil
}

// UpdateTokens applies `change` to all the tokens.RefreshTokens in the Datastore that match the ID,
// ProfileID, or ClientID constraints of `change`.
func (d *Datastore) UpdateTokens(ctx context.Context, change tokens.RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	var keys []*datastore.Key

	if change.ID != "" {
		keys = append(keys, d.key(change.ID))
	}
	if change.ProfileID != "" {
		q := datastore.NewQuery(datastoreTokenKind).Filter("ProfileID =", change.ProfileID).KeysOnly()
		if d.namespace != "" {
			q = q.Namespace(d.namespace)
		}
		res, err := d.client.GetAll(ctx, q, nil)
		if err != nil {
			return err
		}
		keys = append(keys, res...)
	}
	if change.ClientID != "" {
		q := datastore.NewQuery(datastoreTokenKind).Filter("ClientID =", change.ClientID).KeysOnly()
		if d.namespace != "" {
			q = q.Namespace(d.namespace)
		}
		res, err := d.client.GetAll(ctx, q, nil)
		if err != nil {
			return err
		}
		keys = append(keys, res...)
	}
	for pos, key := range keys {
		keys[pos] = d.useKey(key.Name)
	}
	// TODO(paddy): this is buggy, it will set Used or Revoked to false if they're already set and we try to update the other
	use := datastoreTokenUse{
		Timestamp: time.Now(),
		IsRevoke:  change.Revoked != nil && *change.Revoked,
		IsUse:     change.Used != nil && *change.Used,
	}
	if !use.IsRevoke && !use.IsUse {
		// if the values are going to be false, get rid of the record
		return d.client.DeleteMulti(ctx, keys)
	}
	vals := make([]datastoreTokenUse, 0, len(keys))
	for i := 0; i < len(keys); i++ {
		vals = append(vals, use)
	}
	_, err := d.client.PutMulti(ctx, keys, vals)
	return err
}

// UseToken atomically marks the token specified by `id` as used, returning
// tokens.ErrTokenUsed if the token has already been used, or
// tokens.ErrTokenNotFound if the token doesn't exist.
func (d *Datastore) UseToken(ctx context.Context, id string) error {
	var tok datastoreToken
	err := d.client.Get(ctx, d.key(id), &tok)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return tokens.ErrTokenNotFound
		}
		return err
	}
	use := datastoreTokenUse{
		Timestamp: time.Now(),
		IsUse:     true,
	}
	mut := datastore.NewInsert(d.useKey(id), &use)
	_, err = d.client.Mutate(ctx, mut)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return tokens.ErrTokenUsed
		}
		return err
	}
	return nil
}

// GetTokensByProfileID retrieves up to NumTokenResults tokens.RefreshTokens from the Datastore.
// Only tokens.RefreshTokens with a ProfileID property matching `profileID` will be returned. If `since`
// is non-empty, only tokens.RefreshTokens with a CreatedAt property that is after `since` will be
// returned. If `before` is non-empty, only tokens.RefreshTokens with a CreatedAt property that is
// before `before` will be returned. tokens.RefreshTokens will be sorted by their CreatedAt property,
// with the most recent coming first.
func (d *Datastore) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]tokens.RefreshToken, error) {
	// TODO(paddy): Limit to 25 results
	// TODO(paddy): filter by since
	// TODO(paddy): filter by before
	q := datastore.NewQuery(datastoreTokenKind).Filter("ProfileID =", profileID).KeysOnly()
	if d.namespace != "" {
		q = q.Namespace(d.namespace)
	}
	keys, err := d.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	toks := make([]datastoreToken, len(keys))
	err = d.client.GetMulti(ctx, keys, toks)
	if err != nil {
		return nil, err
	}
	results := make([]tokens.RefreshToken, 0, len(toks))
	for pos, tok := range toks {
		tok.ID = keys[pos].Name
		results = append(results, fromDatastore(tok))
	}

	// retrieve the revocation/use data for each token
	for pos, key := range keys {
		keys[pos] = d.useKey(key.Name)
	}
	uses := make([]datastoreTokenUse, len(keys))
	err = d.client.GetMulti(ctx, keys, uses)
	if err != nil {
		// some of our tokens may not be used or revoked, in which case
		// they wouldn't have a key in the results here. We need to filter
		// out the key-not-found errors, but still bubble up the real errors.
		if me, ok := err.(datastore.MultiError); ok {
			for pos, e := range me {
				// if there's no error, the key for this position was
				// found with no problems, so let's update the token
				// in this position.
				if e == nil {
					tok := results[pos]
					tok.Used = uses[pos].IsUse
					tok.Revoked = uses[pos].IsRevoke
					results[pos] = tok
				} else if e == datastore.ErrNoSuchEntity {
					// if we have a NoSuchEntity error, we can
					// ignore it, that token hasn't been used yet
					continue
				} else {
					// if we have an error that's not
					// NoSuchEntity, return the original error,
					// this is a bad request
					return nil, err
				}
			}
			// if this isn't a MultiError, it's definitely a real error
		} else {
			return nil, err
		}
	} else {
		// if there's no error, every token is used or revoked, so update
		// them all
		for pos, use := range uses {
			tok := results[pos]
			tok.Used = use.IsUse
			tok.Revoked = use.IsRevoke
			results[pos] = tok
		}
	}
	// TODO(paddy): sort by CreatedAt
	return results, nil
}
