package tokens

import (
	"fmt"

	"golang.org/x/net/context"
)

func init() {
	storerFactories = append(storerFactories, MemstoreFactory{})
}

type MemstoreFactory struct{}

func (m MemstoreFactory) NewStorer(ctx context.Context) (Storer, error) {
	return NewMemstore(), nil
}

func (m MemstoreFactory) TeardownStorer(ctx context.Context, storer Storer) error {
	memstore, ok := storer.(*Memstore)
	if !ok {
		return fmt.Errorf("Storer was not a *Memstore, was %T", storer)
	}
	memstore.tokens = nil
	return nil
}
