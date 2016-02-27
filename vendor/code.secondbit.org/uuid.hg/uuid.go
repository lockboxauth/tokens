package uuid

import (
	"database/sql/driver"
	"errors"

	"github.com/pborman/uuid"
)

var InvalidIDError = errors.New("Invalid ID format.")

type ID uuid.UUID

func NewID() ID {
	return ID(uuid.NewRandom())
}

func (id ID) String() string {
	return uuid.UUID(id).String()
}

func (id ID) IsZero() bool {
	if id == nil {
		return true
	}
	if len(id) == 0 {
		return true
	}
	return false
}

func (id ID) Copy() ID {
	resp, _ := Parse(id.String())
	// ignore the error because they asked for a copy of the ID, they
	// never asked if it was valid or not.
	// This is, overall, not the most efficient way to do this (we're
	// essentially converting to a string and then back again) but the
	// computational complexity involved is pretty minor, and it allows
	// us to respect the boundaries between the packages, using only the
	// exported interfaces to perform a copy. And that seems pretty
	// valuable.
	return resp
}

func (id ID) MarshalJSON() ([]byte, error) {
	return uuid.UUID(id).MarshalJSON()
}

func (id ID) Value() (driver.Value, error) {
	return id.String(), nil
}

func (id *ID) Scan(src interface{}) error {
	return (*uuid.UUID)(id).Scan(src)
}

func (id *ID) UnmarshalJSON(in []byte) error {
	return (*uuid.UUID)(id).UnmarshalJSON(in)
}

func Parse(in string) (ID, error) {
	id := ID(uuid.Parse(in))
	if id == nil {
		return id, InvalidIDError
	}
	return id, nil
}

func (id ID) Equal(other ID) bool {
	return uuid.Equal(uuid.UUID(id), uuid.UUID(other))
}
