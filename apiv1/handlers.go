package apiv1

import (
	"net/http"

	"impractical.co/auth/tokens"

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
		a.Log.WithError(err).Debug("Error decoding request.")
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: api.InvalidFormatError})
		return
	}
	token := coreToken(body)
	token, err = tokens.FillTokenDefaults(token)
	if err != nil {
		a.Log.WithError(err).Error("Error filling token defaults.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
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
			api.Encode(w, r, http.StatusBadRequest, Response{Errors: []api.RequestError{{Field: "/id", Slug: api.RequestErrConflict}}})
			return
		}
		a.Log.WithError(err).Error("Error creating token.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
		return
	}
	api.Encode(w, r, http.StatusCreated, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handleGetToken(w http.ResponseWriter, r *http.Request) {
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		a.Log.WithField("var", "id").Debug("Empty required request variable.")
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	log := a.Log.WithField("token_id", id)
	token, err := a.Storer.GetToken(r.Context(), id)
	if err == tokens.ErrTokenNotFound {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrNotFound, Param: "{id}"}}})
		return
	} else if err != nil {
		log.WithError(err).Error("Error retrieving token.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
		return
	}
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handlePatchToken(w http.ResponseWriter, r *http.Request) {
	var body RefreshTokenChange
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		a.Log.WithField("var", "id").Debug("Empty required request variable.")
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	log := a.Log.WithField("token_id", id)
	token, err := a.Storer.GetToken(r.Context(), id)
	if err == tokens.ErrTokenNotFound {
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrNotFound, Param: "{id}"}}})
		return
	} else if err != nil {
		log.WithError(err).Error("Error retrieving token.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
		return
	}
	err = api.Decode(r, &body)
	if err != nil {
		log.WithError(err).Debug("Error decoding request body.")
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: api.InvalidFormatError})
		return
	}
	body.ID = id
	change := coreChange(body)
	err = a.Storer.UpdateTokens(r.Context(), change)
	if err != nil {
		log.WithError(err).Error("Error updating token.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
		return
	}
	token = tokens.ApplyChange(token, change)
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}

func (a APIv1) handlePostToken(w http.ResponseWriter, r *http.Request) {
	var body string
	id := trout.RequestVars(r).Get("id")
	if id == "" {
		a.Log.WithField("var", "id").Debug("Empty required request variable.")
		api.Encode(w, r, http.StatusNotFound, Response{Errors: []api.RequestError{{Slug: api.RequestErrMissing, Param: "{id}"}}})
		return
	}
	log := a.Log.WithField("token_id", id)
	err := api.Decode(r, &body)
	if err != nil {
		log.WithError(err).Debug("Error decoding request.")
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: api.InvalidFormatError})
		return
	}
	token, err := a.Validate(r.Context(), body)
	if err == tokens.ErrInvalidToken {
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: []api.RequestError{{Slug: api.RequestErrInvalidValue, Field: "/"}}})
		return
	} else if err == tokens.ErrTokenUsed || err == tokens.ErrTokenRevoked {
		log.WithError(err).Debug("Token revoked or used.")
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: []api.RequestError{{Slug: api.RequestErrConflict, Field: "/"}}})
		return
	} else if err != nil {
		log.WithError(err).Error("Error validating token.")
		api.Encode(w, r, http.StatusInternalServerError, Response{Errors: api.ActOfGodError})
		return
	}
	if id != token.ID {
		log.Debug("Body ID doesn't match URL ID.")
		api.Encode(w, r, http.StatusBadRequest, Response{Errors: []api.RequestError{{Slug: api.RequestErrInvalidValue, Param: "{id}"}}})
		return
	}
	api.Encode(w, r, http.StatusOK, Response{Tokens: []RefreshToken{apiToken(token)}})
}
