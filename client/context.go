package tokensClient

import (
	"errors"

	"golang.org/x/net/context"
)

const (
	managerCtxKey = "darlinggo.co/tokens/client#Manager"
)

var (
	// ErrManagerKeyNotInContext is returned when the managerCtxKey is not set in a context.Context.
	ErrManagerKeyNotInContext = errors.New("managerCtxKey has no value in passed Context")
	// ErrManagerKeyNotManager is returned when the managerCtxKey is set in a context.Context, but its
	// value doesn't fulfill the Manager interface.
	ErrManagerKeyNotManager = errors.New("managerCtxKey does not hold a valid Manager")
)

// ManagerFromContext returns a Manager implementation from the passed context.Context.
func ManagerFromContext(ctx context.Context) (Manager, error) {
	i := ctx.Value(managerCtxKey)
	if i == nil {
		return nil, ErrManagerKeyNotInContext
	}
	m, ok := i.(Manager)
	if !ok {
		return nil, ErrManagerKeyNotManager
	}
	return m, nil
}

// InContext returns a copy of the passed context.Context, with the managerCtxKey
// set to the passed Manager.
func InContext(ctx context.Context, m Manager) context.Context {
	return context.WithValue(ctx, managerCtxKey, m)
}
