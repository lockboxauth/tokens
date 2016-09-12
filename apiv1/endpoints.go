package apiv1

import (
	"context"
	"net/http"

	"darlinggo.co/trout"
)

// Server returns an http.Handler that is configured to handle
// all the routes necessary to serve a devices API server.
func (a APIv1) Server(ctx context.Context, baseURL string) http.Handler {
	var router trout.Router
	router.SetPrefix(baseURL)
	router.Endpoint("/").Methods("POST").Handler(http.HandlerFunc(a.handleInsertToken))
	router.Endpoint("/{id}").Methods("GET").Handler(http.HandlerFunc(a.handleGetToken))
	router.Endpoint("/{id}").Methods("PATCH").Handler(http.HandlerFunc(a.handlePatchToken))

	return router
}
