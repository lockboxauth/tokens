package pqarrays

import (
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
)

var (
	// ErrUnexpectedValueType is returned when the passed value is not a string or []byte.
	ErrUnexpectedValueType = errors.New("expected value to be a string or []byte")
)

// StringArray represents a Postgres array as a []string.
type StringArray []string

// Value implements the Valuer interface for StringArray, allowing it to be transparently
// stored in Postgres databases using the database/sql package.
func (s StringArray) Value() (driver.Value, error) {
	output := make([]string, 0, len(s))
	for _, item := range s {
		item = strconv.Quote(item)
		item = strings.Replace(item, "'", "\\'", -1)
		output = append(output, item)
	}
	return []byte(`{` + strings.Join(output, ",") + `}`), nil
}

// Scan implements the Scanner interface for StringArray, allowing it to be transparently
// retrieved from Postgres databases using the database/sql package. It expects `value` to
// be a string or []byte, and throws ErrUnexpectedValueType when any other type is encountered.
func (s *StringArray) Scan(value interface{}) error {
	*s = (*s)[:0]
	var input string
	if _, ok := value.(string); ok {
		input = value.(string)
	} else if _, ok := value.([]byte); ok {
		input = string(value.([]byte))
	} else {
		return ErrUnexpectedValueType
	}
	l := lex(input)
	parsed, err := parse(l)
	if err != nil {
		return err
	}
	for _, item := range parsed {
		if item == nil {
			continue
		}
		*s = append(*s, *item)
	}
	return nil
}
