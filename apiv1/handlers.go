package apiv1

import (
	"net/http"

	"darlinggo.co/tokens"

	"code.secondbit.org/trout.hg"
	"darlinggo.co/api"
	"golang.org/x/net/context"
)

// all these handlers are written on the assumption that this service will only be exposed
// internally. So there's no authorization or anything on any of them.

func handleInsertToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var body RefreshToken
	err := api.Decode(r, &body)
	if err != nil {
		api.Encode(w, r, http.StatusBadRequest, api.InvalidFormatError)
		return
	}
	token := coreToken(body)
	token, err = tokens.FillTokenDefaults(token)
	if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	var reqErrs []api.RequestError
	if token.CreatedFrom == "" {
		reqErrs = append(reqErrs, api.RequestError{Field: "/createdFrom", Slug: api.RequestErrMissing})
	}
	if token.ProfileID == "" {
		reqErrs = append(reqErrs, api.RequestError{Field: "/profileID", Slug: api.RequestErrMissing})
	}
	if token.ClientID == "" {
		reqErrs = append(reqErrs, api.RequestError{Field: "/clientID", Slug: api.RequestErrMissing})
	}
	if len(reqErrs) > 0 {
		api.Encode(w, r, http.StatusBadRequest, reqErrs)
		return
	}
	err = tokens.Create(ctx, token)
	if err != nil {
		// BUG(paddy): need to throw error if token with same ID already exists
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	api.Encode(w, r, http.StatusCreated, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func handleGetToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	token, err := tokens.Get(ctx, id)
	if err == tokens.ErrTokenNotFound {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrNotFound, Param: "{id}"}}})
		return
	} else if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func handlePatchToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var body RefreshTokenChange
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	token, err := tokens.Get(ctx, id)
	if err == tokens.ErrTokenNotFound {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrNotFound, Param: "{id}"}}})
		return
	} else if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	err = api.Decode(r, &body)
	if err != nil {
		api.Encode(w, r, http.StatusBadRequest, api.InvalidFormatError)
		return
	}
	change := coreChange(body)
	err = tokens.Update(ctx, change)
	if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	token = tokens.ApplyChange(token, change)
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}
