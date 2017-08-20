package storers

import (
	"context"

	"impractical.co/auth/tokens"
)

func init() {
	storerFactories = append(storerFactories, MemstoreFactory{})
}

type MemstoreFactory struct{}

func (m MemstoreFactory) NewStorer(ctx context.Context) (tokens.Storer, error) {
	return NewMemstore()
}

func (m MemstoreFactory) TeardownStorer() error {
	return nil
}
