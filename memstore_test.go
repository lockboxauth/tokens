package tokens

import "context"

func init() {
	storerFactories = append(storerFactories, MemstoreFactory{})
}

type MemstoreFactory struct{}

func (m MemstoreFactory) NewStorer(ctx context.Context) (Storer, error) {
	return NewMemstore(), nil
}

func (m MemstoreFactory) TeardownStorer() error {
	return nil
}
