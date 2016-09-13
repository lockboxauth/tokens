package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/rubenv/sql-migrate"

	"darlinggo.co/version"

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
	db, err := sql.Open("postgres", postgres)
	if err != nil {
		log.Printf("Error connecting to Postgres: %+v\n", err)
		os.Exit(1)
	}
	migrations := &migrate.AssetMigrationSource{
		Asset:    tokens.Asset,
		AssetDir: tokens.AssetDir,
		Dir:      "sql",
	}
	_, err = migrate.Exec(db, "postgres", migrations, migrate.Up)
	if err != nil {
		log.Printf("Error running migrations for Postgres: %+v\n", err)
		os.Exit(1)
	}
	storer, err := tokens.NewPostgres(ctx, db)
	if err != nil {
		log.Printf("Error setting up Postgres: %+v\n", err)
		os.Exit(1)
	}
	v1 := apiv1.APIv1{Dependencies: tokens.Dependencies{Storer: storer}}

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
