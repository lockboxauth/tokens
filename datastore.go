package tokens

import (
	"log"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/cloud"
	"google.golang.org/cloud/datastore"
)

const (
	tokenDatastoreKind = "Token"
)

type Datastore struct {
	client *datastore.Client
}

func (r RefreshToken) DatastoreKey(ctx context.Context) *datastore.Key {
	return newTokenKey(ctx, r.ID)
}

func newTokenKey(ctx context.Context, id string) *datastore.Key {
	return datastore.NewKey(ctx, tokenDatastoreKind, id, 0, nil)
}

func NewDatastore(ctx context.Context, projectID string, opts ...cloud.ClientOption) (Datastore, error) {
	client, err := datastore.NewClient(ctx, projectID, opts...)
	if err != nil {
		return Datastore{}, err
	}
	return Datastore{client: client}, nil
}

func (d Datastore) GetToken(ctx context.Context, id string) (RefreshToken, error) {
	var token RefreshToken
	err := d.client.Get(ctx, newTokenKey(ctx, id), &token)
	if err == datastore.ErrNoSuchEntity {
		err = ErrTokenNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	token.ID = id
	return token, nil
}

func (d Datastore) CreateToken(ctx context.Context, token RefreshToken) error {
	tx, err := d.client.NewTransaction(ctx)
	if err != nil {
		return err
	}
	var res RefreshToken
	if err := tx.Get(token.DatastoreKey(ctx), &res); err != datastore.ErrNoSuchEntity {
		if err == nil {
			return ErrTokenAlreadyExists
		}
		return err
	}
	if _, err := tx.Put(token.DatastoreKey(ctx), &token); err != nil {
		return err
	}
	if _, err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (d Datastore) UpdateTokens(ctx context.Context, change RefreshTokenChange) error {
	if change.IsEmpty() {
		return nil
	}
	var keys []*datastore.Key
	var err error
	switch {
	case change.ID != "":
		keys = append(keys, newTokenKey(ctx, change.ID))
	case change.ProfileID != "":
		query := datastore.NewQuery(tokenDatastoreKind).Filter("ProfileID =", change.ProfileID).KeysOnly()
		var res []*RefreshToken
		keys, err = d.client.GetAll(ctx, query, &res)
		if err != nil {
			return err
		}
	case change.ClientID != "":
		query := datastore.NewQuery(tokenDatastoreKind).Filter("ClientID =", change.ClientID)
		var res []*RefreshToken
		keys, err = d.client.GetAll(ctx, query, &res)
		if err != nil {
			return err
		}
	}
	tx, err := d.client.NewTransaction(ctx)
	if err != nil {
		return err
	}
	tokens := make([]*RefreshToken, len(keys))
	var realTokens []*RefreshToken
	var realKeys []*datastore.Key
	err = tx.GetMulti(keys, tokens)
	if err != nil {
		// if any tokens aren't found, we don't want to insert them
		// if there's a problem retrieving a token, bail out entirely
		// we can do this because GetMulti can return a MultiError
		// which is a slice of errors with a one-to-one correspondence
		// with the input elements.
		if m, ok := err.(datastore.MultiError); ok {
			for pos, e := range m {
				switch e {
				case datastore.ErrNoSuchEntity:
					log.Printf("Tried to update token that didn't exist: %s\n", keys[pos])
					continue
				case nil:
					realKeys = append(realKeys, keys[pos])
					realTokens = append(realTokens, tokens[pos])
				default:
					return err
				}
			}
		} else {
			return err
		}
	} else {
		realTokens = tokens
		realKeys = keys
	}
	if len(realTokens) < 1 {
		return nil
	}
	for pos, token := range realTokens {
		t := ApplyChange(*token, change)
		realTokens[pos] = &t
	}
	_, err = tx.PutMulti(realKeys, realTokens)
	if err != nil {
		return err
	}
	_, err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d Datastore) GetTokensByProfileID(ctx context.Context, profileID string, since, before time.Time) ([]RefreshToken, error) {
	query := datastore.NewQuery(tokenDatastoreKind).Filter("ProfileID =", profileID)
	if !since.IsZero() {
		query = query.Filter("CreatedAt >", since)
	}
	if !before.IsZero() {
		query = query.Filter("CreatedAt <", before)
	}
	query = query.Order("-CreatedAt").Limit(NumTokenResults)
	var tokens []*RefreshToken
	keys, err := d.client.GetAll(ctx, query, &tokens)
	if err != nil {
		return []RefreshToken{}, err
	}
	var results []RefreshToken
	for pos, t := range tokens {
		if t == nil {
			continue
		}
		t.ID = keys[pos].Name()
		results = append(results, *t)
	}
	return results, nil
}
