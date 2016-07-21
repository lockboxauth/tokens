package version

import (
	"encoding/json"
	"net/http"

	"bitbucket.org/ww/goautoneg"
)

func init() {
	json, err := json.Marshal(map[string]string{
		"hash":      Hash,
		"tag":       Tag,
		"branch":    Branch,
		"timestamp": Timestamp,
	})
	if err != nil {
		panic(err)
	}
	jsonOutput = json
}

var (
	// Hash is the VCS hash the binary was built from.
	Hash string
	// Tag is the VCS tag the binary was built from.
	Tag string
	// Branch is the VCS branch the binary was built from.
	Branch string
	// Timestamp is the time the binary was built.
	Timestamp string

	jsonOutput []byte

	// Handler is an http.Handler that exposes the versioning
	// information as an endpoint.
	Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := goautoneg.Negotiate(r.Header.Get("Accept"), []string{"application/json"})
		if contentType == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonOutput)
			return
		}
		w.Write([]byte("VERSION_HASH=\"" + Hash + "\"\nVERSION_TAG=\"" + Tag + "\"\nVERSION_BRANCH=\"" + Branch + "\"\nVERSION_TIME=\"" + Timestamp + "\""))
	})
)
