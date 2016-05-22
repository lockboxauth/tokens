package tokensClient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"

	"darlinggo.co/api"
	"darlinggo.co/tokens/version"

	"bitbucket.org/ww/goautoneg"

	"golang.org/x/net/context"
)

var (
	encodings = []string{"application/json"}
	// ErrUnsupportedEncoding is returned when an HTTP response uses a Content-Type
	// the client can't decode.
	ErrUnsupportedEncoding = errors.New("unsupported encoding")
	// ErrServerError is returned when the server responds, but responds with an error.
	ErrServerError = errors.New("server error")
	// ErrInvalidRequestFormat is returned when the server reports it is unable to decode
	// the request we sent.
	ErrInvalidRequestFormat = errors.New("invalid request format")
)

// UnexpectedNumberOfTokens is a struct used as an error when the client expected a certain
// number of tokens in a response, but got a different number. The tokens received are embedded
// as the Tokens property.
type UnexpectedNumberOfTokens struct {
	Tokens []Token
}

// Error fulfills the error interface. We always return a static string, but having the struct
// allows us to type-cast errors and retrieve the results for debug information.
func (u UnexpectedNumberOfTokens) Error() string {
	return "unexpected number of tokens"
}

// ErrUnexpectedNumberOfTokens returns an error signifying the client was looking for a certain
// number of tokens, but got a different number. The tokens retrieved are embedded in the Tokens
// property of the UnexpectedNumberOfTokens type returned.
func ErrUnexpectedNumberOfTokens(t []Token) error {
	return UnexpectedNumberOfTokens{Tokens: t}
}

type response struct {
	Tokens []Token            `json:"tokens,omitempty"`
	Errors []api.RequestError `json:"errors,omitempty"`
}

// Doer turns an *http.Request into an *http.Response, or errors trying.
// It's mostly useful for creating a mock of the client.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// APIManager is an implementation of the Manager interface that's backed
// by an HTTP API.
type APIManager struct {
	BaseURL     string
	Application string
	doer        Doer
}

func (a APIManager) buildURL(p string) string {
	return path.Join(a.BaseURL, p)
}

func (a APIManager) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Application-ID", a.Application)
	if version.Version != "" {
		req.Header.Set("Tokens-Client-Version", version.Version)
	}
	if version.Hash != "" {
		req.Header.Set("Tokens-Client-Hash", version.Hash)
	}
	hostname, err := os.Hostname()
	if err == nil {
		req.Header.Set("Hostname", hostname)
	}
}

// NewAPIManager returns an APIManager instance that's ready to be used
// as a Manager.
func NewAPIManager(client Doer, baseURL, application string) *APIManager {
	httpClient := client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &APIManager{
		BaseURL:     baseURL,
		Application: application,
		doer:        httpClient,
	}
}

// Get retrieves a single Token from the API. If the ID passed can't be
// found, Get returns an ErrTokenNotFound error.
func (a *APIManager) Get(ctx context.Context, token string) (Token, error) {
	req, err := http.NewRequest("GET", a.buildURL("/"+token), nil)
	if err != nil {
		return Token{}, err
	}
	a.setHeaders(req)
	resp, err := a.doer.Do(req)
	if err != nil {
		return Token{}, err
	}
	var r response
	err = decode(resp, &r)
	if err != nil {
		return Token{}, err
	}
	err = api.DecodeErrors(resp, r.Errors, []api.ErrorDef{
		{Test: api.ActOfGodDef, Err: ErrServerError},
		{Test: api.InvalidFormatDef, Err: ErrInvalidRequestFormat},
		{Test: api.ParamNotFoundDef("{id}"), Err: ErrTokenNotFound},
	})
	if err != nil {
		return Token{}, err
	}
	if len(r.Tokens) != 1 {
		return Token{}, ErrUnexpectedNumberOfTokens(r.Tokens)
	}
	return r.Tokens[0], nil
}

// Insert inserts the passed Token into the service exposed by the API.
func (a *APIManager) Insert(ctx context.Context, token Token) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	err := enc.Encode(token)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", a.buildURL("/"), &buf)
	if err != nil {
		return "", err
	}
	a.setHeaders(req)
	resp, err := a.doer.Do(req)
	if err != nil {
		return "", err
	}
	var r response
	err = decode(resp, &r)
	if err != nil {
		return "", err
	}
	err = api.DecodeErrors(resp, r.Errors, []api.ErrorDef{
		{Test: api.ActOfGodDef, Err: ErrServerError},
		{Test: api.InvalidFormatDef, Err: ErrInvalidRequestFormat},
	})
	if len(r.Tokens) != 1 {
		return "", ErrUnexpectedNumberOfTokens(r.Tokens)
	}
	return r.Tokens[0].ID, nil
}

// Revoke marks the Token identified by the passed ID as revoked, usually for
// security purposes.
func (a *APIManager) Revoke(ctx context.Context, token string) error {
	buf := bytes.NewBufferString(`{"revoked": true}`)
	req, err := http.NewRequest("PATCH", a.buildURL("/"+token), buf)
	if err != nil {
		return err
	}
	a.setHeaders(req)
	resp, err := a.doer.Do(req)
	if err != nil {
		return err
	}
	var r response
	err = decode(resp, &r)
	if err != nil {
		return err
	}
	err = api.DecodeErrors(resp, r.Errors, []api.ErrorDef{
		{Test: api.ActOfGodDef, Err: ErrServerError},
		{Test: api.InvalidFormatDef, Err: ErrInvalidRequestFormat},
		{Test: api.ParamNotFoundDef("{id}"), Err: ErrTokenNotFound},
	})
	return err
}

// Use marks the Token identified by the passed ID as used, signaling that it
// should not be considered valid in future requests.
func (a *APIManager) Use(ctx context.Context, token string) error {
	buf := bytes.NewBufferString(`{"used": true}`)
	req, err := http.NewRequest("PATCH", a.buildURL("/"+token), buf)
	if err != nil {
		return err
	}
	a.setHeaders(req)
	resp, err := a.doer.Do(req)
	if err != nil {
		return err
	}
	var r response
	err = decode(resp, &r)
	if err != nil {
		return err
	}
	err = api.DecodeErrors(resp, r.Errors, []api.ErrorDef{
		{Test: api.ActOfGodDef, Err: ErrServerError},
		{Test: api.InvalidFormatDef, Err: ErrInvalidRequestFormat},
		{Test: api.ParamNotFoundDef("{id}"), Err: ErrTokenNotFound},
	})
	return err
}

func decode(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()
	contentType := goautoneg.Negotiate(resp.Header.Get("Content-Type"), encodings)
	switch contentType {
	case "application/json":
		dec := json.NewDecoder(resp.Body)
		return dec.Decode(target)
	default:
		return ErrUnsupportedEncoding
	}
}
