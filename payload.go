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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	sha2562 "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
)

const (
	KeyTypeRsa = "RSA"
	KeyTypeEc  = "EC"
)

// Key is used to parse the public keys ina JWKS endpoint.
// All properties defined by https://www.rfc-editor.org/rfc/rfc7517#section-4.1 and
// https://www.rfc-editor.org/rfc/rfc7518
type Key struct {
	Algorithm     string   `json:"alg"`     // https://www.rfc-editor.org/rfc/rfc7518#section-3.1
	KeyType       string   `json:"kty"`     // RSA, EC
	KeyOperations []string `json:"key_ops"` // sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits
	Use           string   `json:"use"`     // sig, enc
	KeyId         string   `json:"kid"`     // a unique id for a key

	//x509
	X509Thumbprint       string   `json:"x5t"`      //sha1 of der bytes
	X509ThumbprintSha256 string   `json:"x5t#S256"` //sha256 of der bytes
	X509Chain            []string `json:"x5c"`      // array of base64 certificate DER
	X509Url              string   `json:"x5u"`      // URI pointing to an array of pem certs

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

// NewKey will convert an *x509.Certificate to a Key. If keyId is empty string, the keyId will be populated
// with the sha1 fingerprint/thumbprint of the certificate. Supports RSA and EC keys only.
func NewKey(keyId string, cert *x509.Certificate, chain []*x509.Certificate) (*Key, error) {
	sha1print := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
	sha256print := fmt.Sprintf("%x", sha2562.Sum256(cert.Raw))

	if keyId == "" {
		keyId = sha1print
	}

	ret := Key{
		Algorithm:            "",
		KeyType:              "",
		KeyOperations:        []string{"sign", "verify"},
		Use:                  "sig",
		KeyId:                keyId,
		X509Thumbprint:       sha1print,
		X509ThumbprintSha256: sha256print,
		X509Chain:            nil,
		X509Url:              "",
		Curve:                "",
		X:                    "",
		Y:                    "",
		N:                    "",
		E:                    "",
		K:                    "",
		D:                    "",
		P:                    "",
		Q:                    "",
		Dp:                   "",
		Dq:                   "",
		Qi:                   "",
		T:                    "",
	}

	chainLen := len(chain)
	if chainLen > 0 {
		ret.X509Chain = make([]string, 0, len(chain))

		for _, cert := range chain {
			derStr := base64.RawURLEncoding.EncodeToString(cert.Raw)
			ret.X509Chain = append(ret.X509Chain, derStr)
		}
	}

	if rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		ret.KeyType = KeyTypeRsa
		ret.N = base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())

		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, int32(rsaPubKey.E))

		if err != nil {
			return nil, fmt.Errorf("error encoding RSA exponent: %s", err)
		}

		ret.E = base64.RawURLEncoding.EncodeToString(buf.Bytes())

	} else if ecPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		ret.KeyType = KeyTypeEc

		ret.Curve = ecPubKey.Curve.Params().Name
		ret.X = base64.RawURLEncoding.EncodeToString(ecPubKey.X.Bytes())
		ret.Y = base64.RawURLEncoding.EncodeToString(ecPubKey.Y.Bytes())

	} else {
		return nil, errors.New("invalid public key type, expected EC or RSA public key")
	}

	return &ret, nil
}

// KeyToPublicKey converts the JSON marshalled Key to an interface{} object which represents a
// public key that may be backed by rsa.PublicKey or ecdsa.Public key depending on the input
// key's KeyType.
func KeyToPublicKey(key Key) (interface{}, error) {
	switch key.KeyType {
	case KeyTypeRsa:
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)

		if err != nil {
			return nil, fmt.Errorf("error base64 decoding key's N: %s: %s", key.N, err)
		}
		n := &big.Int{}
		n.SetBytes(nBytes)

		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)

		if err != nil {
			return nil, fmt.Errorf("error base64 decoding key's E: %s: %s", key.E, err)
		}
		e := &big.Int{}
		e.SetBytes(eBytes)

		rsaPubKey := &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}

		return rsaPubKey, nil
	case KeyTypeEc:
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)

		if err != nil {
			return nil, fmt.Errorf("error base64 decoding key's X: %s: %s", key.X, err)
		}

		x := &big.Int{}
		x.SetBytes(xBytes)

		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)

		if err != nil {
			return nil, fmt.Errorf("error base64 decoding key's Y: %s: %s", key.Y, err)
		}

		y := &big.Int{}
		y.SetBytes(yBytes)

		ecPubKey := &ecdsa.PublicKey{
			Curve: curveFromName(key.Curve),
			X:     x,
			Y:     y,
		}

		return ecPubKey, nil
	default:
		return nil, fmt.Errorf("unsuportted key type: %s", key.KeyType)
	}
}

// curveFromName returns the elliptic.Curve implementation based on the input curve name. If the curve name is unknown
// nil is returned.
func curveFromName(curveName string) elliptic.Curve {
	switch curveName {
	case elliptic.P224().Params().Name:
		return elliptic.P224()
	case elliptic.P256().Params().Name:
		return elliptic.P256()
	case elliptic.P384().Params().Name:
		return elliptic.P384()
	case elliptic.P521().Params().Name:
		return elliptic.P521()
	}
	return nil
}
