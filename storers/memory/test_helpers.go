package memory

import (
	"context"

	"lockbox.dev/tokens"
)

type Factory struct{}

func (f Factory) NewStorer(ctx context.Context) (tokens.Storer, error) {
	return NewStorer()
}

func (f Factory) TeardownStorer() error {
	return nil
}
