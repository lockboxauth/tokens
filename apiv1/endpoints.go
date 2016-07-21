package apiv1

import (
	"net/http"

	"darlinggo.co/api"
	"darlinggo.co/trout"
	"golang.org/x/net/context"
)

// GetRouter returns a trout Router that is configured to handle
// all the routes necessary to serve a devices API server.
func GetRouter(ctx context.Context, baseURL string) http.Handler {
	var router trout.Router
	router.SetPrefix(baseURL)
	router.Endpoint("/").Methods("POST").Handler(api.ContextWrapper(ctx, handleInsertToken))
	router.Endpoint("/{id}").Methods("GET").Handler(api.ContextWrapper(ctx, handleGetToken))
	router.Endpoint("/{id}").Methods("PATCH").Handler(api.ContextWrapper(ctx, handlePatchToken))

	return router
}
