package tokens

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"sync"

	_ "github.com/mattes/migrate/driver/postgres"
	"github.com/mattes/migrate/migrate"

	"golang.org/x/net/context"
)

func init() {
	if os.Getenv("PG_TEST_DB") == "" {
		return
	}
	storerConn, err := sql.Open("postgres", os.Getenv("PG_TEST_DB"))
	if err != nil {
		panic(err)
	}
	storerFactories = append(storerFactories, &PostgresFactory{db: storerConn})
}

type PostgresFactory struct {
	db    *sql.DB
	count int
	lock  sync.Mutex
}

func (p *PostgresFactory) NewStorer(ctx context.Context) (context.Context, Storer, error) {
	p.lock.Lock()
	p.count++
	count := p.count
	p.lock.Unlock()
	_, err := p.db.Exec("CREATE DATABASE tokens_test_" + strconv.Itoa(count) + ";")
	if err != nil {
		log.Printf("Error creating database tokens_test_%d: %+v\n", count, err)
		return ctx, nil, err
	}

	u, err := url.Parse(os.Getenv("PG_TEST_DB"))
	if err != nil {
		log.Printf("Error parsing PG_TEST_DB as a URL: %+v\n", err)
		return ctx, nil, err
	}
	if u.Scheme != "postgres" {
		return ctx, nil, errors.New("PG_TEST_DB must begin with postgres://")
	}
	u.Path = "/tokens_test_" + strconv.Itoa(count)

	migrations := os.Getenv("PG_MIGRATIONS_DIR")
	if migrations == "" {
		migrations = "./sql"
	}
	errs, ok := migrate.UpSync(u.String(), migrations)
	if !ok {
		return ctx, nil, fmt.Errorf("Error setting up database %s: %+v\n", u.String(), errs)
	}

	storer, err := NewPostgres(ctx, u.String())
	if err != nil {
		return ctx, nil, err
	}
	return ctx, storer, nil
}

func (p *PostgresFactory) TeardownStorer(ctx context.Context, storer Storer) error {
	pgStorer, ok := storer.(Postgres)
	if !ok {
		return fmt.Errorf("Expected Storer to be Postgres, got %T\n", storer)
	}
	query := "SELECT current_database();"
	var tableName string
	err := pgStorer.db.QueryRow(query).Scan(&tableName)
	if err != nil {
		return err
	}
	pgStorer.db.Close()
	_, err = p.db.Exec("DROP DATABASE " + tableName + ";")
	if err != nil {
		return err
	}
	return nil
}
