package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"

	"bitbucket.org/ww/goautoneg"

	"code.secondbit.org/uuid.hg"

	"golang.org/x/net/context"
)

const (
	RequestErrAccessDenied  = "access_denied"
	RequestErrInsufficient  = "insufficient"
	RequestErrOverflow      = "overflow"
	RequestErrInvalidValue  = "invalid_value"
	RequestErrInvalidFormat = "invalid_format"
	RequestErrMissing       = "missing"
	RequestErrNotFound      = "not_found"
	RequestErrConflict      = "conflict"
	RequestErrActOfGod      = "act_of_god"
)

var (
	ActOfGodError      = []RequestError{{Slug: RequestErrActOfGod}}
	InvalidFormatError = []RequestError{{Slug: RequestErrInvalidFormat, Field: "/"}}
	AccessDeniedError  = []RequestError{{Slug: RequestErrAccessDenied}}

	Encoders = []string{"application/json"}

	ErrUserIDNotSet = errors.New("user ID not set")
)

type RequestError struct {
	Slug   string `json:"error,omitempty"`
	Field  string `json:"field,omitempty"`
	Param  string `json:"param,omitempty"`
	Header string `json:"header,omitempty"`
}

type ContextHandler func(context.Context, http.ResponseWriter, *http.Request)

func NegotiateMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "" {
			contentType := goautoneg.Negotiate(r.Header.Get("Accept"), Encoders)
			if contentType == "" {
				w.WriteHeader(http.StatusNotAcceptable)
				w.Write([]byte("Unsupported content type requested: " + r.Header.Get("Accept")))
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func Encode(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	contentType := goautoneg.Negotiate(r.Header.Get("Accept"), Encoders)
	w.Header().Set("content-type", contentType)
	w.WriteHeader(status)
	var err error
	switch contentType {
	case "application/json":
		enc := json.NewEncoder(w)
		err = enc.Encode(resp)
	default:
		enc := json.NewEncoder(w)
		err = enc.Encode(resp)
	}
	if err != nil {
		log.Println(err)
	}
}

func Decode(r *http.Request, target interface{}) error {
	defer r.Body.Close()
	switch r.Header.Get("Content-Type") {
	case "application/json":
		dec := json.NewDecoder(r.Body)
		return dec.Decode(target)
	default:
		dec := json.NewDecoder(r.Body)
		return dec.Decode(target)
	}
}

func CORSMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if strings.ToLower(r.Method) == "options" {
			methods := strings.Join(r.Header[http.CanonicalHeaderKey("Trout-Methods")], ", ")
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Allow", methods)
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func ContextWrapper(c context.Context, handler ContextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(c, w, r)
	})
}

func CheckScopes(scopes []string, checking ...string) bool {
	sort.Strings(scopes)
	for _, scope := range checking {
		found := sort.SearchStrings(scopes, scope)
		if found == len(scopes) || scopes[found] != scope {
			return false
		}
	}
	return true
}

func GetScopes(r *http.Request) []string {
	scopes := strings.Split(r.Header.Get("scopes"), " ")
	for pos, scope := range scopes {
		scopes[pos] = strings.TrimSpace(scope)
	}
	sort.Strings(scopes)
	return scopes
}

func AuthUser(r *http.Request) (uuid.ID, error) {
	rawID := r.Header.Get("User-ID")
	if rawID == "" {
		return nil, ErrUserIDNotSet
	}
	return uuid.Parse(rawID)
}