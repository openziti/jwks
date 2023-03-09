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
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"github.com/Jeffail/gabs/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

var testPublicJwksAuth0 = `{
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "4SEOORSe1V6Ic-_LSbFJaERGxTwBhHt2zHluYO449sYEi7um4Q-ZodseaUw4R1uLvIG_Eh7mJwGi37-To8woYzCLz3fvdF7G5Pq-tm78A4VLC9_WrvBOgP9PXYaGzPcz60JTJb5Ee94jrWYVwLJUGX_AXnjKUAJXFhAVGlrpeCRMhJx625XIQEchNjdotMxe_kPwM9dgmG_zRe0IH98UbuqYTYUwdkH_INe7IL7jJF3tDm2571yAbH_unqdpTvrrb3CkU0f-AIwb-GlYxR2aQ8jNaGGJSx0EI_G89BHMZAGJpRlPXwjD5qrn2QC06XOG9JDrLyDen2Z2R-TYCfkkjw",
            "e": "AQAB",
            "kid": "nDNaLwW5uTxoHZ5vLiTui",
            "x5t": "MMp-6VIvEYOnYoGjvky-Wxk_h0A",
            "x5c": [
                "MIIDDTCCAfWgAwIBAgIJZgHXXsVCojHCMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1qYTI4b2p6ay51cy5hdXRoMC5jb20wHhcNMjIwMzAzMTgxNjM4WhcNMzUxMTEwMTgxNjM4WjAkMSIwIAYDVQQDExlkZXYtamEyOG9qemsudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SEOORSe1V6Ic+/LSbFJaERGxTwBhHt2zHluYO449sYEi7um4Q+ZodseaUw4R1uLvIG/Eh7mJwGi37+To8woYzCLz3fvdF7G5Pq+tm78A4VLC9/WrvBOgP9PXYaGzPcz60JTJb5Ee94jrWYVwLJUGX/AXnjKUAJXFhAVGlrpeCRMhJx625XIQEchNjdotMxe/kPwM9dgmG/zRe0IH98UbuqYTYUwdkH/INe7IL7jJF3tDm2571yAbH/unqdpTvrrb3CkU0f+AIwb+GlYxR2aQ8jNaGGJSx0EI/G89BHMZAGJpRlPXwjD5qrn2QC06XOG9JDrLyDen2Z2R+TYCfkkjwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRrO/lcE6fRDss+WAroJw0I3sZQ1zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAChrBHmfIbEOOKdtOs5zfLgZKjwXMQ3NydYHSCPrZKKNrR2JLYRy3KD3iLUZmqgb3kiWqO+aVABAHNi3H3oGTTIEklRH69NMpbmTs+W9suw/JaIrbj2HCPbTCGMvA5yTo3kABJbVapHCO8cd8FCZVCa5+CbdMBsjvnZvUNriX69VAHIzRIv/AGQbHXWQoU7igRm9nLnO/BKFhWPXiSuYpaBz5uqg+qB3gfyGUQjeAoYo5b3YtZt/GrwcQS5Ku4lhV7jPkAgEyQdHAC6RKw7Gf/p+u58gSMKXeZxW9FxgGNMsQPuKTyIEuikYinT70Y1IUsMAaqS5SrzglvPYgZpYTmc="
            ]
        },
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "-VLOzBGDO1mRgwz6ZWK4aTyebQI5blRifFrhjax-bH_hbFaNZ1LjFZNUJ7wR1GfrXUtI_2bZF-QBeGPD_rfwrPuAVktyysGWpyTeTUJSbdotWyhDN7v6_ySvQcLjQVajRslGiUUn9eBNDvQm8HyAgmUEOFZk5m0kdSh2sU3fB-Q71OGYHm_uTSENGgtnVp7pvXJVoD26-ZKf_6movrrQ8lPX_SBFL79JIGwcV-Q35PkwKpLDmfR5qsiruQcgAOrcU83UEujrHumgJFM2SV_7pP1lW83itYBizeShUXDkMnEsarenNwBs2ej4CHF4wlg8kvAuvM1etP9wTvQgR8pCTw",
            "e": "AQAB",
            "kid": "9OcLRMTskCwYepHJAgyc4",
            "x5t": "AQFCuQ1CEs-mkKBan4LOQS0AsbM",
            "x5c": [
                "MIIDDTCCAfWgAwIBAgIJUE+YLL7UA3KIMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1qYTI4b2p6ay51cy5hdXRoMC5jb20wHhcNMjIwMzAzMTgxNjM4WhcNMzUxMTEwMTgxNjM4WjAkMSIwIAYDVQQDExlkZXYtamEyOG9qemsudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+VLOzBGDO1mRgwz6ZWK4aTyebQI5blRifFrhjax+bH/hbFaNZ1LjFZNUJ7wR1GfrXUtI/2bZF+QBeGPD/rfwrPuAVktyysGWpyTeTUJSbdotWyhDN7v6/ySvQcLjQVajRslGiUUn9eBNDvQm8HyAgmUEOFZk5m0kdSh2sU3fB+Q71OGYHm/uTSENGgtnVp7pvXJVoD26+ZKf/6movrrQ8lPX/SBFL79JIGwcV+Q35PkwKpLDmfR5qsiruQcgAOrcU83UEujrHumgJFM2SV/7pP1lW83itYBizeShUXDkMnEsarenNwBs2ej4CHF4wlg8kvAuvM1etP9wTvQgR8pCTwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSwhiE0zXOLZkCeCDIibq6gx1x9VzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAMyRiIbglAop3eSX/DzS27OJe2vVMd9pCUBV/WeCSIt41Cv1ZHW15sklCyr5mGN27MrYK50h/vb4JcHRTLrUZ2L0Ib5ogcxeQTWzTpcK8VEKT4bUZhJeOoqWxjBEZi/mo8EqadY0NMzEy0mAUTJzOtfJv8eSoRE1ElwTb6AQiTFLHtcK2MLEDWNIXWVOVew5OTVRJLJd4r5jgL9DcuVFY/sWLn7LgV71P9bjZnvGx8FuWouYsnjMT/YhfUhs+n+JPCX7SEHn3rn5XXGN6KyEYzBLrouQHRu+y3x7aYCWwW1Hr94EbvGaD/dSzH+zAMmk635mrmM1JXXYGeIVp0xKP5s="
            ]
        }
    ]
}`

var testJwksRfc7517Examples = `
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use": "enc",
      "kid": "1"
    },
    {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "2011-04-29"
    },
	{
	  "kty": "RSA",
	  "kid": "juliet@capulet.lit",
	  "use": "enc",
	  "n": "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q",
	  "e": "AQAB",
	  "d": "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
	  "p": "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws",
	  "q": "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s",
	  "dp": "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c",
	  "dq": "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots",
	  "qi": "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"
	}
  ]
}`

func Test_Response(t *testing.T) {
	t.Run("can parse auth0 example jwks", func(t *testing.T) {
		req := require.New(t)
		response := &Response{}

		err := json.Unmarshal([]byte(testPublicJwksAuth0), response)
		req.NoError(err)

		t.Run("parses without error", func(t *testing.T) {
			req := require.New(t)
			req.NoError(err)
		})

		t.Run("results in a non-nil response", func(t *testing.T) {
			req := require.New(t)
			req.NotNil(response)
		})

		t.Run("has the expected properties", func(t *testing.T) {
			req := require.New(t)

			jwksContainer, err := gabs.ParseJSON([]byte(testPublicJwksAuth0))
			req.NoError(err)
			req.NotNil(jwksContainer)

			req.Equal(jwksContainer.Path("keys.0.alg").Data(), response.Keys[0].Algorithm)
			req.Equal(jwksContainer.Path("keys.0.kty").Data(), response.Keys[0].KeyType)
			req.Equal(jwksContainer.Path("keys.0.use").Data(), response.Keys[0].Use)
			req.Equal(jwksContainer.Path("keys.0.n").Data(), response.Keys[0].N)
			req.Equal(jwksContainer.Path("keys.0.e").Data(), response.Keys[0].E)
			req.Equal(jwksContainer.Path("keys.0.kid").Data(), response.Keys[0].KeyId)
			req.Equal(jwksContainer.Path("keys.0.x5t").Data(), response.Keys[0].X509Thumbprint)
			req.Equal(jwksContainer.Path("keys.0.x5c.0").Data(), response.Keys[0].X509Chain[0])

			req.Equal(jwksContainer.Path("keys.1.alg").Data(), response.Keys[1].Algorithm)
			req.Equal(jwksContainer.Path("keys.1.kty").Data(), response.Keys[1].KeyType)
			req.Equal(jwksContainer.Path("keys.1.use").Data(), response.Keys[1].Use)
			req.Equal(jwksContainer.Path("keys.1.n").Data(), response.Keys[1].N)
			req.Equal(jwksContainer.Path("keys.1.e").Data(), response.Keys[1].E)
			req.Equal(jwksContainer.Path("keys.1.kid").Data(), response.Keys[1].KeyId)
			req.Equal(jwksContainer.Path("keys.1.x5t").Data(), response.Keys[1].X509Thumbprint)
			req.Equal(jwksContainer.Path("keys.1.x5c.0").Data(), response.Keys[1].X509Chain[0])
		})
	})

	t.Run("can parse rfc7517 example jwks", func(t *testing.T) {
		req := require.New(t)
		response := &Response{}

		err := json.Unmarshal([]byte(testJwksRfc7517Examples), response)
		req.NoError(err)

		t.Run("parses without error", func(t *testing.T) {
			req := require.New(t)
			req.NoError(err)
		})

		t.Run("results in a non-nil response", func(t *testing.T) {
			req := require.New(t)
			req.NotNil(response)
		})

		t.Run("has the expected properties", func(t *testing.T) {
			req := require.New(t)

			jwksContainer, err := gabs.ParseJSON([]byte(testJwksRfc7517Examples))
			req.NoError(err)
			req.NotNil(jwksContainer)

			req.Equal(jwksContainer.Path("keys.0.kty").Data(), response.Keys[0].KeyType)
			req.Equal(jwksContainer.Path("keys.0.crv").Data(), response.Keys[0].Curve)
			req.Equal(jwksContainer.Path("keys.0.x").Data(), response.Keys[0].X)
			req.Equal(jwksContainer.Path("keys.0.y").Data(), response.Keys[0].Y)
			req.Equal(jwksContainer.Path("keys.0.use").Data(), response.Keys[0].Use)
			req.Equal(jwksContainer.Path("keys.0.kid").Data(), response.Keys[0].KeyId)

			req.Equal(jwksContainer.Path("keys.1.kty").Data(), response.Keys[1].KeyType)
			req.Equal(jwksContainer.Path("keys.1.n").Data(), response.Keys[1].N)
			req.Equal(jwksContainer.Path("keys.1.e").Data(), response.Keys[1].E)
			req.Equal(jwksContainer.Path("keys.1.alg").Data(), response.Keys[1].Algorithm)
			req.Equal(jwksContainer.Path("keys.1.kid").Data(), response.Keys[1].KeyId)

			req.Equal(jwksContainer.Path("keys.2.kty").Data(), response.Keys[2].KeyType)
			req.Equal(jwksContainer.Path("keys.2.kid").Data(), response.Keys[2].KeyId)
			req.Equal(jwksContainer.Path("keys.2.use").Data(), response.Keys[2].Use)
			req.Equal(jwksContainer.Path("keys.2.n").Data(), response.Keys[2].N)
			req.Equal(jwksContainer.Path("keys.2.e").Data(), response.Keys[2].E)
			req.Equal(jwksContainer.Path("keys.2.d").Data(), response.Keys[2].D)
			req.Equal(jwksContainer.Path("keys.2.p").Data(), response.Keys[2].P)
			req.Equal(jwksContainer.Path("keys.2.q").Data(), response.Keys[2].Q)
			req.Equal(jwksContainer.Path("keys.2.dq").Data(), response.Keys[2].Dq)
			req.Equal(jwksContainer.Path("keys.2.qi").Data(), response.Keys[2].Qi)

			t.Run("can create rsa.PublicKey from JWK without x5c", func(t *testing.T) {
				req := require.New(t)

				pubKey, err := KeyToPublicKey(response.Keys[1])

				req.NoError(err)
				req.NotNil(pubKey)

				rsaPubKey := pubKey.(*rsa.PublicKey)
				req.NotNil(rsaPubKey)

				req.Equal("26634547600177008912365441464036882611104634136430581696102639463075266436216946316053845642300166320042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655738647387007320361149854766523417293323739185308113373529512728932838100141612048712597178695720651344295450174895369923383396704334331627261565907266749863744707920606364678231639106403854977302183719246256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285432062044391310047445749287563161668548354322560223509946990827691654627968182167826397015368836435965354956581554819", rsaPubKey.N.String())
				req.Equal(65537, rsaPubKey.E)
			})

			t.Run("can create ecdsa.PublicKey from JWK without x5c", func(t *testing.T) {
				req := require.New(t)

				pubKey, err := KeyToPublicKey(response.Keys[0])

				req.NoError(err)
				req.NotNil(pubKey)

				ecPubKey := pubKey.(*ecdsa.PublicKey)
				req.NotNil(ecPubKey)

				req.Equal("P-256", ecPubKey.Curve.Params().Name)
				req.Equal("101451294974385619524093058399734017814808930032421185206609461750712400090915", ecPubKey.Y.String())
				req.Equal("21994169848703329112137818087919262246467304847122821377551355163096090930238", ecPubKey.X.String())
			})
		})
	})

}
