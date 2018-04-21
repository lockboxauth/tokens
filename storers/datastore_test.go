package storers

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"sync"

	"cloud.google.com/go/datastore"
	"github.com/hashicorp/go-uuid"
	"google.golang.org/api/option"

	"impractical.co/auth/tokens"
)

func init() {
	if os.Getenv("DATASTORE_TEST_PROJECT") == "" || os.Getenv("DATASTORE_TEST_CREDS") == "" {
		return
	}
	client, err := datastore.NewClient(context.Background(), os.Getenv("DATASTORE_TEST_PROJECT"), option.WithServiceAccountFile(os.Getenv("DATASTORE_TEST_CREDS")))
	if err != nil {
		panic(err)
	}
	storerFactories = append(storerFactories, NewDatastoreFactory(client))
}

type DatastoreFactory struct {
	client     *datastore.Client
	namespaces []string
	lock       sync.Mutex
}

func NewDatastoreFactory(client *datastore.Client) *DatastoreFactory {
	return &DatastoreFactory{client: client}
}

func (d *DatastoreFactory) NewStorer(ctx context.Context) (tokens.Storer, error) {
	namespace, err := uuid.GenerateRandomBytes(6)
	if err != nil {
		log.Printf("Error generating namespace: %s", err.Error())
		return nil, err
	}
	d.lock.Lock()
	d.namespaces = append(d.namespaces, "test_"+hex.EncodeToString(namespace))
	d.lock.Unlock()

	storer, err := NewDatastore(ctx, d.client)
	if err != nil {
		return nil, err
	}
	storer.namespace = "test_" + hex.EncodeToString(namespace)

	return storer, nil
}

func (d *DatastoreFactory) TeardownStorer() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	for _, namespace := range d.namespaces {
		q := datastore.NewQuery(datastoreTokenKind).Namespace(namespace).KeysOnly()
		keys, err := d.client.GetAll(context.Background(), q, nil)
		if err != nil {
			log.Printf("Error cleaning up tokens in namespace %q: %s", namespace, err.Error())
			continue
		}
		err = d.client.DeleteMulti(context.Background(), keys)
		if err != nil {
			log.Printf("Error cleaning up tokens in namespace %q: %s", namespace, err.Error())
			continue
		}

		q = datastore.NewQuery(datastoreTokenUseKind).Namespace(namespace).KeysOnly()
		keys, err = d.client.GetAll(context.Background(), q, nil)
		if err != nil {
			log.Printf("Error cleaning up tokens in namespace %q: %s", namespace, err.Error())
			continue
		}
		err = d.client.DeleteMulti(context.Background(), keys)
		if err != nil {
			log.Printf("Error cleaning up tokens in namespace %q: %s", namespace, err.Error())
			continue
		}
	}
	return nil
}
