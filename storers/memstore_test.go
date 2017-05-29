package storers

import (
	"context"

	"code.impractical.co/tokens"
)

func init() {
	storerFactories = append(storerFactories, MemstoreFactory{})
}

type MemstoreFactory struct{}

func (m MemstoreFactory) NewStorer(ctx context.Context) (tokens.Storer, error) {
	return NewMemstore(), nil
}

func (m MemstoreFactory) TeardownStorer() error {
	return nil
}
