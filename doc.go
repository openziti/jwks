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

// Package jwks provides low level facilities for parsing JWKs endpoint responses according to RFC7517. It provides
// the basic JWK and JWK Set (JWKS) JSON parsing structs Response (`keys`) and Key (`[]key`). It also provides a small
// utility function and interface to obtain and parse a JWKS endpoint over string defined locations such as via
// URLs for HTTP(S).
//
// Basic resolver usage:
// ```
//	resolver := &HttpResolver{}
//	resp, rawPayload, err := resolver.Get("https://myhost/.well-known/jwks.json")
// ```
// Basic parser usage:
// ```
//	response := &Response{}
//	err := json.Unmarshal([]byte(`{"keys": [...]}`), response)
// ```
//
package jwks
