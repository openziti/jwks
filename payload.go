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

// Key is used to parse the public keys ina JWKS endpoint
type Key struct {
	Algorithm     string `json:"alg"`
	KeyType       string `json:"kty"`
	KeyOperations string `json:"key_ops"`
	Use           string `json:"use"`
	KeyId         string `json:"kid"`

	//x509
	X509Thumbprint       string   `json:"x5t"`
	X509ThumbprintSha256 string   `json:"x5t#S256"`
	X509Chain            []string `json:"x5c"`
	X509Url              string   `json:"x5u"`

	//public ec kty="ec"
	Curve string `json:"crv"` //ec curve
	X     string `json:"x"`   // ec x curve coordinate
	Y     string `json:"y"`   // ec y curve coordinate

	//public rsa kty="rsa"
	N string `json:"n"` // rsa modulus
	E string `json:"e"` // rsa public exponent

	//symmetric kty="oct"
	K string `json:"k"` // symmetric key

	//private key properties
	D  string `json:"d"`  // rsa private exponent / ec private key
	P  string `json:"p"`  // rsa secret prime
	Q  string `json:"q"`  // rsa secret prime
	Dp string `json:"dp"` // rsa private key parameter
	Dq string `json:"dq"` // rsa private key parameter
	Qi string `json:"qi"` // rsa private key parameter

	//byok
	T string `json:"t"` //bring your own key property
}

// Response is used to parse a JWKS endpoint response, it contains zero or more Key instances
type Response struct {
	Keys []Key `json:"keys"`
}
