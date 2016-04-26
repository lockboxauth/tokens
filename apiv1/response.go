package apiv1

import "darlinggo.co/api"

// Response is a global response object; it supplies the format all
// HTTP responses should be returned in.
type Response struct {
	Tokens []RefreshToken     `json:"tokens,omitempty"`
	Errors []api.RequestError `json:"errors,omitempty"`
}
