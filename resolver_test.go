/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
package jwks

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func Test_HttpResolver(t *testing.T) {
	req := require.New(t)

	port := "1280"
	urlBase := "http://localhost:" + port
	urlValidPath := "/.well-known/jwks.json"
	urlWrongContentTypePath := "/invalid/content-type"
	urlEmptyContentPath := "/invalid/no-content"
	urlBadContentPath := "/invalid/mangled-json"

	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case urlValidPath:
			rw.Header().Set("content-type", "application/json")
			_, _ = rw.Write([]byte(testPublicJwksAuth0))
		case urlWrongContentTypePath:
			rw.Header().Set("content-type", "plain/text")
			_, _ = rw.Write([]byte(testPublicJwksAuth0))
		case urlEmptyContentPath:
			rw.Header().Set("content-type", "application/json")
			_, _ = rw.Write([]byte(""))
		case urlBadContentPath:
			rw.Header().Set("content-type", "application/json")
			_, _ = rw.Write([]byte(`{"hello": invalid-json[]}`))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	})}

	go func() {
		err := server.ListenAndServe()

		if err != nil && err.Error() != "http: Server closed" {
			req.NoError(err)
		}
	}()

	defer func() {
		err := server.Shutdown(context.Background())
		req.NoError(err)
	}()

	t.Run("can resolve and parse a valid JWKS response", func(t *testing.T) {
		req := require.New(t)

		resolver := &HttpResolver{}

		resp, rawPayload, err := resolver.Get(urlBase + urlValidPath)
		req.NoError(err)
		req.NotNil(resp)
		req.Equal(testPublicJwksAuth0, string(rawPayload))
	})

	t.Run("can not resolve and parse a 404", func(t *testing.T) {
		req := require.New(t)

		resolver := &HttpResolver{}

		resp, rawPayload, err := resolver.Get(urlBase + "/made-up-path")
		req.Error(err)
		req.Nil(resp)
		req.Nil(rawPayload)
	})

	t.Run("can not resolve and parse the wrong content-type", func(t *testing.T) {
		req := require.New(t)

		resolver := &HttpResolver{}

		resp, rawPayload, err := resolver.Get(urlBase + urlWrongContentTypePath)
		req.Error(err)
		req.Nil(resp)
		req.Nil(rawPayload)
	})

	t.Run("can not resolve and parse empty content", func(t *testing.T) {
		req := require.New(t)

		resolver := &HttpResolver{}

		resp, rawPayload, err := resolver.Get(urlBase + urlEmptyContentPath)
		req.Error(err)
		req.Nil(resp)
		req.Nil(rawPayload)
	})

	t.Run("can not resolve and parse empty content", func(t *testing.T) {
		req := require.New(t)

		resolver := &HttpResolver{}

		resp, rawPayload, err := resolver.Get(urlBase + urlBadContentPath)
		req.Error(err)
		req.Nil(resp)
		req.Nil(rawPayload)
	})
}
