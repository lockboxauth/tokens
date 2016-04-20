package tokens

import (
	"fmt"
	"io/ioutil"
	"os"

	"code.secondbit.org/uuid.hg"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/cloud"
	"google.golang.org/cloud/datastore"
)

func init() {
	if os.Getenv("DATASTORE_TEST_PROJECT") == "" || os.Getenv("DATASTORE_TEST_AUTH") == "" {
		return
	}
	storerFactories = append(storerFactories, &DatastoreFactory{})
}

type DatastoreFactory struct {
}

func (d *DatastoreFactory) NewStorer(ctx context.Context) (context.Context, Storer, error) {
	var opts []cloud.ClientOption
	datastoreProjectID := os.Getenv("DATASTORE_TEST_PROJECT")
	switch os.Getenv("DATASTORE_TEST_AUTH") {
	case "jwt-from-json":
		jsonFile := os.Getenv("DATASTORE_TEST_JSON_FILE")
		if jsonFile == "" {
			return ctx, nil, fmt.Errorf("DATASTORE_TEST_JSON_FILE must be set if DATASTORE_TEST_AUTH is jwt-from-json")
		}
		data, err := ioutil.ReadFile(jsonFile)
		if err != nil {
			return ctx, nil, err
		}
		conf, err := google.JWTConfigFromJSON(data, datastore.ScopeDatastore)
		if err != nil {
			return ctx, nil, err
		}
		opts = append(opts, cloud.WithTokenSource(conf.TokenSource(ctx)))
	case "default":
		// do nothing, it's configured by default
	default:
		return ctx, nil, fmt.Errorf("DATASTORE_TEST_PROJECT must be set to default or jwt-from-json")
	}
	newCtx := datastore.WithNamespace(ctx, "tokens_test_"+uuid.NewID().String())
	datastore, err := NewDatastore(newCtx, datastoreProjectID, opts...)
	if err != nil {
		return ctx, nil, err
	}
	return newCtx, datastore, nil
}

func (d *DatastoreFactory) TeardownStorer(ctx context.Context, storer Storer) error {
	dStorer, ok := storer.(Datastore)
	if !ok {
		return fmt.Errorf("Expected Storer to be Datastore, got %T\n", storer)
	}
	dStorer.client = nil
	return nil
}
