package apiv1

import (
	"net/http"

	"code.impractical.co/tokens"

	"darlinggo.co/api"
	"darlinggo.co/trout"
)

// APIv1 handles all the dependencies for the apiv1 package. This is a superset of the
// tokens.Dependencies struct, and a valid Dependencies struct is necessary for a valid
// APIv1 struct.
type APIv1 struct {
	tokens.Dependencies
}

// all these handlers are written on the assumption that this service will only be exposed
// internally. So there's no authorization or anything on any of them.

func (a APIv1) handleInsertToken(w http.ResponseWriter, r *http.Request) {
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
	err = a.Storer.CreateToken(r.Context(), token)
	if err != nil {
		if err == tokens.ErrTokenAlreadyExists {
			api.Encode(w, r, http.StatusBadRequest, []api.RequestError{{Field: "/id", Slug: api.RequestErrConflict}})
			return
		}
		if err == tokens.ErrTokenHashAlreadyExists {
			api.Encode(w, r, http.StatusBadRequest, []api.RequestError{{Field: "/value", Slug: api.RequestErrConflict}})
			return
		}
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	api.Encode(w, r, http.StatusCreated, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handleGetToken(w http.ResponseWriter, r *http.Request) {
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	token, err := a.Storer.GetToken(r.Context(), id)
	if err == tokens.ErrTokenNotFound {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrNotFound, Param: "{id}"}}})
		return
	} else if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handlePatchToken(w http.ResponseWriter, r *http.Request) {
	var body RefreshTokenChange
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	token, err := a.Storer.GetToken(r.Context(), id)
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
	err = a.Storer.UpdateTokens(r.Context(), change)
	if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	token = tokens.ApplyChange(token, change)
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handlePostToken(w http.ResponseWriter, r *http.Request) {
	var body RefreshToken
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	err := api.Decode(r, &body)
	if err != nil {
		api.Encode(w, r, http.StatusBadRequest, api.InvalidFormatError)
		return
	}
	token, err := a.Validate(r.Context(), id, body.Value)
	if err == tokens.ErrInvalidToken {
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: []api.RequestError{{Slug: api.RequestErrInvalidValue}}})
		return
	} else if err != nil {
		api.Encode(w, r, http.StatusInternalServerError, api.ActOfGodError)
		return
	}
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}
