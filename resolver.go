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
	"encoding/json"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	ErrorInvalidStatusCodeMsg  = "could not fetch JWKS, status code was not 200 OK"
	ErrorInvalidContentTypeMsg = "invalid content type, expected application/json"
)

// Resolver takes in a string location and returns the Response and raw response (`[]byte`) JSON or an error
type Resolver interface {
	Get(string) (*Response, []byte, error)
}

// HttpResolver implements Resolver and obtains JWKs responses via HTTP(S)
type HttpResolver struct{}

// HttpResolverError is a generic error type used to relay the the http.Response from a JWKS endpoint to external
// code for inspection
type HttpResolverError struct {
	error
	Resp *http.Response
}

func (j *HttpResolver) Get(url string) (*Response, []byte, error) {

	resp, err := http.Get(url)

	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, &HttpResolverError{
			Resp:  resp,
			error: errors.New(ErrorInvalidStatusCodeMsg),
		}
	}

	contentType := strings.Split(resp.Header.Get("content-type"), ";")

	if contentType[0] != "application/json" && contentType[0] != "application/jwk-set+json" && contentType[0] != "application/jwk+json" {
		return nil, nil, &HttpResolverError{
			Resp:  resp,
			error: errors.New(ErrorInvalidContentTypeMsg),
		}
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, nil, &HttpResolverError{
			Resp:  resp,
			error: err,
		}
	}

	jwksResponse := &Response{}
	err = json.Unmarshal(body, jwksResponse)

	if err != nil {
		return nil, nil, &HttpResolverError{
			Resp:  resp,
			error: err,
		}
	}

	return jwksResponse, body, nil
}
