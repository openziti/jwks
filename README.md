# jwks

Package jwks provides low level facilities for parsing JWKs endpoint responses according to RFC7517. It provides
the basic JWK and JWK Set (JWKS) JSON parsing structs Response (`keys`) and Key (`[]key`). It also provides a small
utility function and interface to obtain and parse a JWKS endpoint over string defined locations such as via
URLs for HTTP(S).

This package aims to have as few dependencies as possible. It is meant to be the base building block for something
grander.

## Add To Your Project:

`go get -u github.com/openziti/jwks@latest`

## Basic resolver usage:
```
resolver := &HttpResolver{}
resp, rawPayload, err := resolver.Get("https://myhost/.well-known/jwks.json")
```

## Basic parser usage:
```
response := &Response{}
err := json.Unmarshal([]byte(`{"keys": [...]}`), response)
```
