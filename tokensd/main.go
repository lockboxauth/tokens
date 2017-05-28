package main

import (
	"context"
	"database/sql"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rubenv/sql-migrate"

	"darlinggo.co/version"

	"code.impractical.co/tokens"
	"code.impractical.co/tokens/apiv1"
)

func main() {
	// set up our logger
	logger := log.New(os.Stdout, "", log.Llongfile|log.LstdFlags|log.LUTC|log.Lmicroseconds)

	ctx := context.Background()

	// Set up postgres connection
	postgres := os.Getenv("PG_DB")
	if postgres == "" {
		logger.Println("Error setting up Postgres: no connection string set.")
		os.Exit(1)
	}
	db, err := sql.Open("postgres", postgres)
	if err != nil {
		logger.Printf("Error connecting to Postgres: %+v\n", err)
		os.Exit(1)
	}
	migrations := &migrate.AssetMigrationSource{
		Asset:    tokens.Asset,
		AssetDir: tokens.AssetDir,
		Dir:      "sql",
	}
	_, err = migrate.Exec(db, "postgres", migrations, migrate.Up)
	if err != nil {
		logger.Printf("Error running migrations for Postgres: %+v\n", err)
		os.Exit(1)
	}
	storer, err := tokens.NewPostgres(ctx, db)
	if err != nil {
		logger.Printf("Error setting up Postgres: %+v\n", err)
		os.Exit(1)
	}

	// set up private RSA key to sign JWTs with
	privateKeyFile := os.Getenv("JWT_PRIVATE_KEY")
	if privateKeyFile == "" {
		logger.Println("Error loading JWT private key: no source file specified.")
		os.Exit(1)
	}
	privKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		logger.Printf("Error reading JWT private key from %s: %+v\n", privateKeyFile, err)
		os.Exit(1)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyBytes)
	if err != nil {
		logger.Printf("Error loading JWT private key from PEM: %+v\n", err)
		os.Exit(1)
	}
	privKeyBytes = nil // unset so it's not floating around in memory

	// set up public RSA key to verify JWT signatures with
	publicKeyFile := os.Getenv("JWT_PUBLIC_KEY")
	if publicKeyFile == "" {
		logger.Println("Error loading JWT public key: no source file specified.")
		os.Exit(1)
	}
	pubKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		logger.Printf("Error reading JWT public key from %s: %+v\n", publicKeyFile, err)
		os.Exit(1)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyBytes)
	if err != nil {
		logger.Printf("Error loading JWT public key from PEM: %+v\n", err)
		os.Exit(1)
	}

	v1 := apiv1.APIv1{
		Dependencies: tokens.Dependencies{
			Storer:        storer,
			JWTPrivateKey: privateKey,
			JWTPublicKey:  publicKey,
			Log:           logger,
		},
	}

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

	logger.Printf("tokensd version %s starting on port 0.0.0.0:4001\n", vers)
	err = http.ListenAndServe("0.0.0.0:4001", nil)
	if err != nil {
		logger.Printf("Error listening on port 0.0.0.0:4001: %+v\n", err)
		os.Exit(1)
	}
}
