package storers

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"code.impractical.co/tokens"

	"github.com/pborman/uuid"
)

const (
	changeUsed = 1 << iota
	changeRevoked
	changeVariations
)

type StorerFactory interface {
	NewStorer(ctx context.Context) (tokens.Storer, error)
	TeardownStorer() error
}

var storerFactories []StorerFactory

func compareRefreshTokens(token1, token2 tokens.RefreshToken) (success bool, field string, val1, val2 interface{}) {
	if token1.ID != token2.ID {
		return false, "ID", token1.ID, token2.ID
	}
	if !token1.CreatedAt.Equal(token2.CreatedAt) {
		return false, "CreatedAt", token1.CreatedAt, token2.CreatedAt
	}
	if token1.CreatedFrom != token2.CreatedFrom {
		return false, "CreatedFrom", token1.CreatedFrom, token2.CreatedFrom
	}
	if len(token1.Scopes) != len(token2.Scopes) {
		return false, "Scopes", token1.Scopes, token2.Scopes
	}
	for pos, scope := range token1.Scopes {
		if scope != token2.Scopes[pos] {
			return false, "Scopes", token1.Scopes, token2.Scopes
		}
	}
	if token1.ProfileID != token2.ProfileID {
		return false, "ProfileID", token1.ProfileID, token2.ProfileID
	}
	if token1.ClientID != token2.ClientID {
		return false, "ClientID", token1.ClientID, token2.ClientID
	}
	if token1.Revoked != token2.Revoked {
		return false, "Revoked", token1.Revoked, token2.Revoked
	}
	if token1.Used != token2.Used {
		return false, "Used", token1.Used, token2.Used
	}
	return true, "", nil, nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	result := m.Run()
	for _, factory := range storerFactories {
		err := factory.TeardownStorer()
		if err != nil {
			log.Printf("Error cleaning up after %T: %+v\n", factory, err)
		}
	}
	os.Exit(result)
}

func TestCreateAndGetToken(t *testing.T) {
	t.Parallel()
	for _, factory := range storerFactories {
		ctx := context.Background()
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			storer, ctx := storer, ctx
			token := tokens.RefreshToken{
				ID: uuid.NewRandom().String(),
				// Postgres only stores times to the millisecond, so we have to round it going in
				CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("test case for %T", storer),
				Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
				ProfileID:   uuid.NewRandom().String(),
				ClientID:    uuid.NewRandom().String(),
				Revoked:     false,
				Used:        true,
			}

			err = storer.CreateToken(ctx, token)
			if err != nil {
				t.Fatalf("Error creating token: %+v\n", err)
			}

			result, err := storer.GetToken(ctx, token.ID)
			if err != nil {
				t.Fatalf("Unexpected error retrieving token: %+v\n", err)
			}
			ok, field, expected, got := compareRefreshTokens(token, result)
			if !ok {
				t.Errorf("Expected %s to be %v, got %v\n", field, expected, got)
			}
		})
	}
}

func TestCreateTokenErrTokenAlreadyExists(t *testing.T) {
	t.Parallel()
	for _, factory := range storerFactories {
		ctx := context.Background()
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			storer, ctx := storer, ctx

			token := tokens.RefreshToken{
				ID: uuid.NewRandom().String(),
				// Postgres only stores times to the millisecond, so we have to round it going in
				CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("test case for %T", storer),
				Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
				ProfileID:   uuid.NewRandom().String(),
				ClientID:    uuid.NewRandom().String(),
				Revoked:     false,
				Used:        true,
			}

			err = storer.CreateToken(ctx, token)
			if err != nil {
				t.Fatalf("Error creating token in %T: %+v\n", storer, err)
			}

			err = storer.CreateToken(ctx, token)
			if err != tokens.ErrTokenAlreadyExists {
				t.Errorf("Expected tokens.ErrTokenAlreadyExists, %T returned %+v\n", storer, err)
			}
		})
	}
}

func TestGetTokenErrTokenNotFound(t *testing.T) {
	t.Parallel()
	for _, factory := range storerFactories {
		ctx := context.Background()
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			storer, ctx := storer, ctx

			token, err := storer.GetToken(ctx, uuid.NewRandom().String())
			if err != tokens.ErrTokenNotFound {
				t.Errorf("Expected tokens.ErrTokenNotFound, %T returned %+v and %+v\n", storer, token, err)
			}
		})
	}
}

func TestCreateUpdateAndGetTokenByID(t *testing.T) {
	t.Parallel()
	for _, factory := range storerFactories {
		ctx := context.Background()
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			storer, ctx := storer, ctx

			token := tokens.RefreshToken{
				// Postgres only stores times to the millisecond, so we have to round it going in
				CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("test case for %T", storer),
				Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
				ProfileID:   uuid.NewRandom().String(),
				ClientID:    uuid.NewRandom().String(),
				Revoked:     false,
				Used:        true,
			}

			for i := 1; i < changeVariations; i++ {
				t.Run(fmt.Sprintf("Variation=%d", i), func(t *testing.T) {
					i := i
					token := token
					t.Parallel()
					var change tokens.RefreshTokenChange
					var revoked, used bool

					token.ID = uuid.NewRandom().String()
					change.ID = token.ID

					expectation := token
					result := token

					if i&changeRevoked != 0 {
						revoked = i%2 == 0
						change.Revoked = &revoked
						expectation.Revoked = revoked
					}
					if i&changeUsed == 0 {
						used = i%2 != 0
						change.Used = &used
						expectation.Used = used
					}
					result = tokens.ApplyChange(result, change)
					ok, field, expectedVal, resultVal := compareRefreshTokens(expectation, result)
					if !ok {
						t.Errorf("Expected %s of change %d to be %v, got %v after applying tokens.RefreshTokenChange %+v\n", field, i, expectedVal, resultVal, change)
					}

					err := storer.CreateToken(ctx, token)
					if err != nil {
						t.Fatalf("Error creating token in %T: %+v\n", storer, err)
					}

					err = storer.UpdateTokens(ctx, change)
					if err != nil {
						t.Fatalf("Error updating token in %T: %+v\n", storer, err)
					}

					resp, err := storer.GetToken(ctx, token.ID)
					if err != nil {
						t.Fatalf("Error retrieving token from %T: %+v\n", storer, err)
					}
					ok, field, expectedVal, resultVal = compareRefreshTokens(expectation, resp)
					if !ok {
						t.Errorf("Expected %s of change %d (ID %s) to be %v, got %v from %T\n", field, i, token.ID, expectedVal, resultVal, storer)
					}
				})
			}
		})
	}
}

func TestCreateAndGetTokensByProfileID(t *testing.T) {
	t.Parallel()
	for _, factory := range storerFactories {
		ctx := context.Background()
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			storer, ctx := storer, ctx
			user1 := uuid.NewRandom().String()
			user2 := uuid.NewRandom().String()

			toks := []tokens.RefreshToken{
				{
					ID: uuid.NewRandom().String(),
					// Postgres only stores times to the millisecond, so we have to round it going in
					CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
					CreatedFrom: fmt.Sprintf("test case for %T", storer),
					Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
					ProfileID:   user1,
					ClientID:    uuid.NewRandom().String(),
					Revoked:     false,
					Used:        true,
				}, {
					ID:          uuid.NewRandom().String(),
					CreatedAt:   time.Now().Add(1 * time.Hour).Round(time.Millisecond),
					CreatedFrom: fmt.Sprintf("second test case for %T", storer),
					Scopes:      []string{"this scope", "that scope"},
					ProfileID:   user1,
					ClientID:    uuid.NewRandom().String(),
					Revoked:     false,
					Used:        false,
				}, {
					ID:          uuid.NewRandom().String(),
					CreatedAt:   time.Now().Add(1 * time.Minute).Round(time.Millisecond),
					CreatedFrom: fmt.Sprintf("third test case for %T", storer),
					ProfileID:   user2,
					ClientID:    uuid.NewRandom().String(),
					Revoked:     true,
					Used:        false,
				},
			}

			for _, token := range toks {
				err = storer.CreateToken(ctx, token)
				if err != nil {
					t.Errorf("Error creating token %+v in %T: %+v\n", token, storer, err)
				}
			}

			expectations := []tokens.RefreshToken{toks[1], toks[0]}

			results, err := storer.GetTokensByProfileID(ctx, user1, time.Time{}, time.Time{})
			if err != nil {
				t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
			}

			if len(expectations) != len(results) {
				t.Logf("%+v\n", expectations)
				t.Fatalf("Expected %d results, got %d from %T: %+v\n", len(expectations), len(results), storer, results)
			}

			for pos, expectation := range expectations {
				ok, field, exp, res := compareRefreshTokens(expectation, results[pos])
				if !ok {
					t.Errorf("Expected %s of token %d to be %v, got %v from %T\n", field, pos, exp, res, storer)
				}
			}

			expectations = []tokens.RefreshToken{toks[0]}

			results, err = storer.GetTokensByProfileID(ctx, user1, time.Time{}, time.Now())
			if err != nil {
				t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
			}

			if len(expectations) != len(results) {
				t.Errorf("Expected %d results, got %d from %T: %+v\n", len(expectations), len(results), storer, results)
			}

			for pos, expectation := range expectations {
				ok, field, exp, res := compareRefreshTokens(expectation, results[pos])
				if !ok {
					t.Errorf("Expected %s of token %d to be %v, got %v from %T\n", field, pos, exp, res, storer)
				}
			}

			expectations = []tokens.RefreshToken{toks[1]}

			results, err = storer.GetTokensByProfileID(ctx, user1, time.Now(), time.Time{})
			if err != nil {
				t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
			}

			if len(expectations) != len(results) {
				t.Errorf("Expected %d results, got %d from %T: %+v\n", len(expectations), len(results), storer, results)
			}

			for pos, expectation := range expectations {
				ok, field, exp, res := compareRefreshTokens(expectation, results[pos])
				if !ok {
					t.Errorf("Expected %s of token %d to be %v, got %v from %T\n", field, pos, exp, res, storer)
				}
			}

			expectations = []tokens.RefreshToken{toks[2]}

			results, err = storer.GetTokensByProfileID(ctx, user2, time.Time{}, time.Time{})
			if err != nil {
				t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
			}

			if len(expectations) != len(results) {
				t.Errorf("Expected %d results, got %d from %T: %+v\n", len(expectations), len(results), storer, results)
			}

			for pos, expectation := range expectations {
				ok, field, exp, res := compareRefreshTokens(expectation, results[pos])
				if !ok {
					t.Errorf("Expected %s of token %d to be %v, got %v from %T\n", field, pos, exp, res, storer)
				}
			}

			expectations = []tokens.RefreshToken{}

			results, err = storer.GetTokensByProfileID(ctx, uuid.NewRandom().String(), time.Time{}, time.Time{})
			if err != nil {
				t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
			}

			if len(expectations) != len(results) {
				t.Errorf("Expected %d results, got %d from %T: %+v\n", len(expectations), len(results), storer, results)
			}
		})
	}
}
