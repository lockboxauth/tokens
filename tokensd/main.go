package main

import (
	"log"
	"net/http"
	"os"

	_ "github.com/mattes/migrate/driver/postgres"
	"github.com/mattes/migrate/migrate"

	"darlinggo.co/tokens"
	"darlinggo.co/tokens/apiv1"
	"golang.org/x/net/context"
)

func main() {
	ctx := context.Background()

	// Set up postgres connection
	postgres := os.Getenv("PG_DB")
	if postgres == "" {
		log.Println("Error setting up Postgres: no connection string set.")
		os.Exit(1)
	}
	storer, err := tokens.NewPostgres(ctx, postgres)
	if err != nil {
		log.Printf("Error setting up Postgres: %+v\n", err)
		os.Exit(1)
	}
	migrations := os.Getenv("PG_MIGRATIONS_DIR")
	if migrations == "" {
		migrations = "../sql"
	}
	errs, ok := migrate.UpSync(postgres, migrations)
	if !ok {
		log.Printf("Error running migrations: %+v\n", errs)
		os.Exit(1)
	}
	ctx = tokens.SetStorer(ctx, storer)

	// Set up API v1 handlers
	v1 := apiv1.GetRouter(ctx, "/v1")
	// we need both to avoid redirecting, which turns POST into GET
	// the slash is needed to handle /v1/*
	http.Handle("/v1/", v1)
	http.Handle("/v1", v1)

	version := tokens.Version
	if version == "undefined" || version == "" {
		version = "dev"
	}
	version = version + " (" + tokens.Hash + ")"

	log.Printf("tokensd version %s starting on port 0.0.0.0:4001\n", version)
	err = http.ListenAndServe("0.0.0.0:4001", nil)
	if err != nil {
		log.Printf("Error listening on port 0.0.0.0:4001: %+v\n", err)
		os.Exit(1)
	}
}
