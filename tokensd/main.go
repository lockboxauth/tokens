package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"darlinggo.co/version"

	_ "github.com/mattes/migrate/driver/postgres"
	"github.com/mattes/migrate/migrate"

	"code.impractical.co/tokens"
	"code.impractical.co/tokens/apiv1"
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
		migrations = "./sql"
	}
	errs, ok := migrate.UpSync(postgres, migrations)
	if !ok {
		log.Printf("Error running migrations: %+v\n", errs)
		os.Exit(1)
	}
	v1 := apiv1.APIv1{tokens.Dependencies{Storer: storer}}

	// we need both to avoid redirecting, which turns POST into GET
	// the slash is needed to handle /v1/*
	http.Handle("/v1/", v1.Server(ctx, "/v1/"))
	http.Handle("/v1", v1.Server(ctx, "/v1"))

	// set up version handler
	http.Handle("/version", version.Handler)

	vers := version.Tag
	if vers == "undefined" || vers == "" {
		vers = "dev"
	}
	vers = vers + " (" + version.Hash + ")"

	log.Printf("tokensd version %s starting on port 0.0.0.0:4001\n", vers)
	err = http.ListenAndServe("0.0.0.0:4001", nil)
	if err != nil {
		log.Printf("Error listening on port 0.0.0.0:4001: %+v\n", err)
		os.Exit(1)
	}
}
