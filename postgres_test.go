package tokens

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"os"
	"sync"

	"github.com/pborman/uuid"
	"github.com/rubenv/sql-migrate"
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
	db        *sql.DB
	databases map[string]*sql.DB
	lock      sync.Mutex
}

func (p *PostgresFactory) NewStorer(ctx context.Context) (Storer, error) {
	u, err := url.Parse(os.Getenv("PG_TEST_DB"))
	if err != nil {
		log.Printf("Error parsing PG_TEST_DB as a URL: %+v\n", err)
		return nil, err
	}
	if u.Scheme != "postgres" {
		return nil, errors.New("PG_TEST_DB must begin with postgres://")
	}

	database := "tokens_test_" + hex.EncodeToString([]byte(uuid.NewRandom()))

	_, err = p.db.Exec("CREATE DATABASE " + database + ";")
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

	p.lock.Lock()
	if p.databases == nil {
		p.databases = map[string]*sql.DB{}
	}
	p.databases[database] = newConn
	p.lock.Unlock()

	migrations := &migrate.AssetMigrationSource{
		Asset:    Asset,
		AssetDir: AssetDir,
		Dir:      "sql",
	}
	_, err = migrate.Exec(newConn, "postgres", migrations, migrate.Up)
	if err != nil {
		return nil, err
	}

	storer, err := NewPostgres(ctx, newConn)
	if err != nil {
		return nil, err
	}
	return storer, nil
}

func (p *PostgresFactory) TeardownStorer() error {
	p.lock.Lock()
	defer p.lock.Unlock()
	for table, conn := range p.databases {
		conn.Close()
		_, err := p.db.Exec("DROP DATABASE " + table + ";")
		if err != nil {
			return err
		}
	}
	p.db.Close()
	return nil
}
