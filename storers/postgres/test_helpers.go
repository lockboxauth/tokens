package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"os"
	"sync"

	uuid "github.com/hashicorp/go-uuid"
	migrate "github.com/rubenv/sql-migrate"

	"lockbox.dev/tokens"
	"lockbox.dev/tokens/storers/postgres/migrations"
)

type Factory struct {
	db        *sql.DB
	databases map[string]*sql.DB
	lock      sync.Mutex
}

func NewFactory(db *sql.DB) *Factory {
	return &Factory{
		db:        db,
		databases: map[string]*sql.DB{},
	}
}

func (f *Factory) NewStorer(ctx context.Context) (tokens.Storer, error) {
	u, err := url.Parse(os.Getenv("PG_TEST_DB"))
	if err != nil {
		log.Printf("Error parsing PG_TEST_DB as a URL: %+v\n", err)
		return nil, err
	}
	if u.Scheme != "postgres" {
		return nil, errors.New("PG_TEST_DB must begin with postgres://")
	}

	databaseSuffix, err := uuid.GenerateRandomBytes(6)
	if err != nil {
		log.Printf("Error generating table suffix: %+v\n", err)
		return nil, err
	}
	database := "tokens_test_" + hex.EncodeToString(databaseSuffix)

	_, err = f.db.Exec("CREATE DATABASE " + database + ";")
	if err != nil {
		log.Printf("Error creating database %s: %+v\n", database, err)
		return nil, err

	}
	u.Path = "/" + database
	newConn, err := sql.Open("postgres", u.String())
	if err != nil {
		log.Println("Accidentally orphaned", database, "it will need to be cleaned up manually")
		return nil, err
	}

	f.lock.Lock()
	if f.databases == nil {
		f.databases = map[string]*sql.DB{}
	}
	f.databases[database] = newConn
	f.lock.Unlock()

	migrations := &migrate.AssetMigrationSource{
		Asset:    migrations.Asset,
		AssetDir: migrations.AssetDir,
		Dir:      "sql",
	}
	_, err = migrate.Exec(newConn, "postgres", migrations, migrate.Up)
	if err != nil {
		return nil, err
	}

	storer := NewStorer(ctx, newConn)
	return storer, nil
}

func (f *Factory) TeardownStorer() error {
	f.lock.Lock()
	defer f.lock.Unlock()
	for table, conn := range f.databases {
		conn.Close()
		_, err := f.db.Exec("DROP DATABASE " + table + ";")
		if err != nil {
			return err
		}
	}
	f.db.Close()
	return nil
}
