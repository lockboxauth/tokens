package tokens_test

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	uuid "github.com/hashicorp/go-uuid"
	yall "yall.in"
	"yall.in/colour"

	"lockbox.dev/tokens"
	"lockbox.dev/tokens/storers/memory"
	"lockbox.dev/tokens/storers/postgres"
)

const (
	changeUsed = 1 << iota
	changeRevoked
	changeVariations
)

const (
	filterID = 1 << iota
	filterProfileID
	filterClientID
	filterAccountID
	filterVariations
)

type Factory interface {
	NewStorer(ctx context.Context) (tokens.Storer, error)
	TeardownStorer() error
}

var factories []Factory

func uuidOrFail(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("Unexpected error generating ID: %s", err.Error())
	}
	return id
}

func TestMain(m *testing.M) {
	flag.Parse()

	// set up our test storers
	factories = append(factories, memory.Factory{})
	if os.Getenv(postgres.TestConnStringEnvVar) != "" {
		storerConn, err := sql.Open("postgres", os.Getenv(postgres.TestConnStringEnvVar))
		if err != nil {
			panic(err)
		}
		factories = append(factories, postgres.NewFactory(storerConn))
	}

	// run the tests
	result := m.Run()

	// tear down all the storers we created
	for _, factory := range factories {
		err := factory.TeardownStorer()
		if err != nil {
			log.Printf("Error cleaning up after %T: %+v\n", factory, err)
		}
	}

	// return the test result
	os.Exit(result)
}

func runTest(t *testing.T, f func(*testing.T, tokens.Storer, context.Context)) {
	t.Parallel()
	logger := yall.New(colour.New(os.Stdout, yall.Debug))
	for _, factory := range factories {
		ctx := yall.InContext(context.Background(), logger)
		storer, err := factory.NewStorer(ctx)
		if err != nil {
			t.Fatalf("Error creating Storer from %T: %+v\n", factory, err)
		}
		t.Run(fmt.Sprintf("Storer=%T", storer), func(t *testing.T) {
			t.Parallel()
			f(t, storer, ctx)
		})
	}
}

func TestCreateAndGetToken(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		token := tokens.RefreshToken{
			ID: uuidOrFail(t),
			// Postgres only stores times to the millisecond, so we have to round it going in
			CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
			CreatedFrom: fmt.Sprintf("test case for %T", storer),
			Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
			AccountID:   uuidOrFail(t),
			ProfileID:   uuidOrFail(t),
			ClientID:    uuidOrFail(t),
			Revoked:     false,
			Used:        true,
		}

		err := storer.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("Error creating token: %+v\n", err)
		}

		result, err := storer.GetToken(ctx, token.ID)
		if err != nil {
			t.Fatalf("Unexpected error retrieving token: %+v\n", err)
		}
		if diff := cmp.Diff(token, result); diff != "" {
			t.Errorf("Unexpected diff (-wanted, +got): %s", diff)
		}
	})
}

func TestCreateTokenErrTokenAlreadyExists(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		token := tokens.RefreshToken{
			ID: uuidOrFail(t),
			// Postgres only stores times to the millisecond, so we have to round it going in
			CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
			CreatedFrom: fmt.Sprintf("test case for %T", storer),
			Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
			AccountID:   uuidOrFail(t),
			ProfileID:   uuidOrFail(t),
			ClientID:    uuidOrFail(t),
			Revoked:     false,
			Used:        true,
		}

		err := storer.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("Error creating token in %T: %+v\n", storer, err)
		}

		err = storer.CreateToken(ctx, token)
		if err != tokens.ErrTokenAlreadyExists {
			t.Errorf("Expected tokens.ErrTokenAlreadyExists, %T returned %+v\n", storer, err)
		}
	})
}

func TestUseTokenErrTokenUsed(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		token := tokens.RefreshToken{
			ID: uuidOrFail(t),
			// Postgres only stores times to the millisecond, so we have to round it going in
			CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
			CreatedFrom: fmt.Sprintf("test case for %T", storer),
			Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
			AccountID:   uuidOrFail(t),
			ProfileID:   uuidOrFail(t),
			ClientID:    uuidOrFail(t),
			Revoked:     false,
			Used:        false,
		}

		err := storer.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("Error creating token in %T: %+v\n", storer, err)
		}
		var usedErrors int
		var successes int
		var wg sync.WaitGroup
		ch := make(chan error)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(w *sync.WaitGroup, c chan error) {
				c <- storer.UseToken(ctx, token.ID)
				w.Done()
			}(&wg, ch)
		}
		go func(w *sync.WaitGroup, c chan error) {
			w.Wait()
			close(c)
		}(&wg, ch)
		for err := range ch {
			if err == tokens.ErrTokenUsed {
				usedErrors++
			} else if err == nil {
				successes++
			} else {
				t.Errorf("Error using token: %s", err)
			}
		}
		if successes != 1 {
			t.Errorf("Expected %d successes, got %d", 1, successes)
		}
		if usedErrors != 19 {
			t.Errorf("Expected %d tokens.ErrTokenUsed errors, got %d", 19, usedErrors)
		}
	})
}

func TestUseTokenErrTokenNotFound(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		err := storer.UseToken(ctx, uuidOrFail(t))
		if err != tokens.ErrTokenNotFound {
			t.Errorf("Expected ErrTokenNotFound, %T returned %+v\n", storer, err)
		}
	})
}

func TestGetTokenErrTokenNotFound(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		token, err := storer.GetToken(ctx, uuidOrFail(t))
		if err != tokens.ErrTokenNotFound {
			t.Errorf("Expected tokens.ErrTokenNotFound, %T returned %+v and %+v\n", storer, token, err)
		}
	})
}

func TestCreateAndGetTokensByProfileID(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		user1 := uuidOrFail(t)
		user2 := uuidOrFail(t)
		user3 := uuidOrFail(t)

		toks := []tokens.RefreshToken{
			{
				ID: uuidOrFail(t),
				// Postgres only stores times to the millisecond, so we have to round it going in
				CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("test case for %T", storer),
				Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
				ProfileID:   user1,
				AccountID:   uuidOrFail(t),
				ClientID:    uuidOrFail(t),
				Revoked:     false,
				Used:        true,
			}, {
				ID:          uuidOrFail(t),
				CreatedAt:   time.Now().Add(1 * time.Hour).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("second test case for %T", storer),
				Scopes:      []string{"this scope", "that scope"},
				ProfileID:   user1,
				AccountID:   uuidOrFail(t),
				ClientID:    uuidOrFail(t),
				Revoked:     false,
				Used:        false,
			}, {
				ID:          uuidOrFail(t),
				CreatedAt:   time.Now().Add(1 * time.Minute).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("third test case for %T", storer),
				ProfileID:   user2,
				AccountID:   uuidOrFail(t),
				ClientID:    uuidOrFail(t),
				Revoked:     true,
				Used:        false,
			},
		}

		var dynamicToks []tokens.RefreshToken
		for i := 0; i < 100; i++ {
			dynamicToks = append(dynamicToks, tokens.RefreshToken{
				ID:          uuidOrFail(t),
				CreatedAt:   time.Now().Add(time.Duration(i) * time.Second).Round(time.Millisecond),
				CreatedFrom: fmt.Sprintf("paginated test case %d for %T", i, storer),
				ProfileID:   user3,
				ClientID:    uuidOrFail(t),
				AccountID:   uuidOrFail(t),
				Revoked:     i%2 == 0,
				Used:        i%2 != 0,
			})
		}
		sort.Slice(dynamicToks, func(i, j int) bool {
			return dynamicToks[i].CreatedAt.After(dynamicToks[j].CreatedAt)
		})

		for _, token := range toks {
			err := storer.CreateToken(ctx, token)
			if err != nil {
				t.Errorf("Error creating token %+v in %T: %+v\n", token, storer, err)
			}
		}
		for _, token := range dynamicToks {
			err := storer.CreateToken(ctx, token)
			if err != nil {
				t.Errorf("Error creating dynamic token %+v in %T: %+v\n", token, storer, err)
			}
		}

		type testcase struct {
			user          string
			expectations  []tokens.RefreshToken
			since, before time.Time
		}
		testcases := []testcase{
			{user: user1, expectations: []tokens.RefreshToken{toks[1], toks[0]}},
			{user: user2, expectations: []tokens.RefreshToken{toks[2]}},
			{user: uuidOrFail(t), expectations: nil},
			{user: user1, before: time.Now(), expectations: []tokens.RefreshToken{toks[0]}},
			{user: user1, since: time.Now(), expectations: []tokens.RefreshToken{toks[1]}},
			{user: user3, expectations: dynamicToks[:tokens.NumTokenResults]},
			{user: user3, before: dynamicToks[tokens.NumTokenResults-1].CreatedAt, expectations: dynamicToks[tokens.NumTokenResults : tokens.NumTokenResults*2]},
			{user: user3, before: dynamicToks[2*tokens.NumTokenResults-1].CreatedAt, expectations: dynamicToks[tokens.NumTokenResults*2 : tokens.NumTokenResults*3]},
			{user: user3, before: dynamicToks[3*tokens.NumTokenResults-1].CreatedAt, expectations: dynamicToks[tokens.NumTokenResults*3 : tokens.NumTokenResults*4]},
		}

		for pos, tc := range testcases {
			pos, tc := pos, tc

			t.Run(fmt.Sprintf("Case=%d", pos), func(t *testing.T) {
				t.Parallel()
				results, err := storer.GetTokensByProfileID(ctx, tc.user, tc.since, tc.before)
				if err != nil {
					t.Fatalf("Error retrieving tokens from %T: %+v\n", storer, err)
				}

				if len(tc.expectations) != len(results) {
					t.Logf("%+v\n", tc.expectations)
					t.Fatalf("Expected %d results, got %d: %+v\n", len(tc.expectations), len(results), results)
				}

				if diff := cmp.Diff(tc.expectations, results); diff != "" {
					t.Errorf("Unexpected diff (-wanted, +got): %s", diff)
				}
			})
		}
	})
}

func TestCreateUpdateTokenNoChangeFilter(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		token := tokens.RefreshToken{
			ID: uuidOrFail(t),
			// Postgres only stores times to the millisecond, so we have to round it going in
			CreatedAt:   time.Now().Add(-1 * time.Hour).Round(time.Millisecond),
			CreatedFrom: fmt.Sprintf("test case for %T", storer),
			Scopes:      []string{"https://scopes.impractical.co/this/is/a/very/long/scope/that/is/pretty/long/I/hope/the/database/can/store/this/super/long/scope/that/is/probably/unrealistically/long/but/still/it's/good/to/test/things/like/this", "https://scopes.impractical.co/profiles/view:me"},
			ProfileID:   uuidOrFail(t),
			AccountID:   uuidOrFail(t),
			ClientID:    uuidOrFail(t),
			Revoked:     false,
			Used:        true,
		}

		var revoked, used bool
		change := tokens.RefreshTokenChange{
			Revoked: &revoked,
			Used:    &used,
		}

		err := storer.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("Error creating token in %T: %+v\n", storer, err)
		}

		err = storer.UpdateTokens(ctx, change)
		if err != tokens.ErrNoTokenChangeFilter {
			t.Errorf("Expected tokens.ErrNoTokenChangeFilter, %T returned %+v\n", storer, err)
		}
	})
}

func TestCreateAndUpdateTokensByFilters(t *testing.T) {
	runTest(t, func(t *testing.T, storer tokens.Storer, ctx context.Context) {
		for filters := 1; filters < filterVariations; filters++ {
			filters := filters
			var filterNames []string
			if filters&filterID != 0 {
				filterNames = append(filterNames, "id")
			}
			if filters&filterProfileID != 0 {
				filterNames = append(filterNames, "profileID")
			}
			if filters&filterClientID != 0 {
				filterNames = append(filterNames, "clientID")
			}
			if filters&filterAccountID != 0 {
				filterNames = append(filterNames, "accountID")
			}
			t.Run(fmt.Sprintf("Filters=%s", strings.Join(filterNames, ",")), func(t *testing.T) {
				for i := 1; i <= changeVariations; i++ {
					i := i
					t.Run(fmt.Sprintf("Variation=%d", i), func(t *testing.T) {
						t.Parallel()
						var change tokens.RefreshTokenChange
						var revoked, used bool
						client1 := uuidOrFail(t)
						client2 := uuidOrFail(t)
						client3 := uuidOrFail(t)

						profile1 := uuidOrFail(t)
						profile2 := uuidOrFail(t)
						profile3 := uuidOrFail(t)

						account1 := uuidOrFail(t)
						account2 := uuidOrFail(t)
						account3 := uuidOrFail(t)

						var client, profile, account string

						toks := make([]tokens.RefreshToken, 0, 300)
						for i := 0; i < 100; i++ {
							cycle := i % 27
							switch cycle % 3 {
							case 0:
								account = account1
							case 1:
								account = account2
							case 2:
								account = account3
							}
							switch {
							case cycle%9 < 3:
								profile = profile1
							case cycle%9 >= 3 && cycle%9 < 6:
								profile = profile2
							case cycle%9 >= 6:
								profile = profile3
							}
							switch {
							case cycle < 9:
								client = client1
							case cycle >= 9 && cycle < 18:
								client = client2
							case cycle >= 18:
								client = client3
							}
							toks = append(toks, tokens.RefreshToken{
								ID:          uuidOrFail(t),
								CreatedAt:   time.Now().Add(time.Duration(i) * time.Second).Round(time.Millisecond),
								CreatedFrom: fmt.Sprintf("test case %d for %T", i, storer),
								ClientID:    client,
								ProfileID:   profile,
								AccountID:   account,
								Revoked:     i%2 == 0,
								Used:        i%2 != 0,
							})
						}
						sort.Slice(toks, func(i, j int) bool {
							return toks[i].CreatedAt.After(toks[j].CreatedAt)
						})

						for _, token := range toks {
							err := storer.CreateToken(ctx, token)
							if err != nil {
								t.Errorf("Error creating token %+v in %T: %+v\n", token, storer, err)
							}
						}

						if filters&filterID != 0 {
							change.ID = toks[20].ID
						}
						if filters&filterProfileID != 0 {
							change.ProfileID = profile2
						}
						if filters&filterClientID != 0 {
							change.ClientID = client3
						}
						if filters&filterAccountID != 0 {
							change.AccountID = account1
						}

						if i&changeRevoked != 0 {
							revoked = i%2 == 0
							change.Revoked = &revoked
						}
						if i&changeUsed != 0 {
							used = i%2 != 0
							change.Used = &used
						}

						err := storer.UpdateTokens(ctx, change)
						if err != nil {
							t.Fatalf("Error updating token in %T: %+v\n", storer, err)
						}
						for _, tok := range toks {
							expectation := tok
							if (change.ID == "" || tok.ID == change.ID) &&
								(change.ProfileID == "" || tok.ProfileID == change.ProfileID) &&
								(change.ClientID == "" || tok.ClientID == change.ClientID) &&
								(change.AccountID == "" || tok.AccountID == change.AccountID) {
								expectation = tokens.ApplyChange(expectation, change)
							}
							result, err := storer.GetToken(ctx, tok.ID)
							if err != nil {
								t.Fatalf("Error retrieving token from %T: %+v\n", storer, err)
							}
							if diff := cmp.Diff(expectation, result); diff != "" {
								t.Errorf("Unexpected diff on change %d (ID %s): %s", i, tok.ID, diff)
							}
						}
					})
				}
			})
		}
	})
}
