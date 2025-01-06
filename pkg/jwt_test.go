package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	secret   = "foobar"
	iss      = "test-iss"
	sub      = "test-sub"
	aud      = "test-aud"
	exp      = 1
	nbf      = 2
	iat      = 3
	jti      = "test-jti"
	jwtRegex = ".+[.].+[.].+"
)

type Foo struct {
	Name string `json:"name"`
}

func TestSignHMAC(t *testing.T) {
	t.Parallel()

	t.Run("should produce an empty claim jwt", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should produce a jwt with no base64 padding", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
		assert.NotContains(t, token, "=")
	})

	t.Run("should allow custom jwt options functions", func(t *testing.T) {
		customHeaderKey := "foo"
		customHeaderVal := "FOO"
		customClaimsKey := "bar"
		customClaimsVal := "BAR"
		token, err := SignHMAC(secret, func(j *JWTOptions) {
			j.Headers[customHeaderKey] = customHeaderVal
			j.Claims[customClaimsKey] = customClaimsVal
		})
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token)
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, customHeaderVal, decoded.Headers[customHeaderKey])
		assert.Equal(t, customClaimsVal, decoded.Claims[customClaimsKey])
	})

	t.Run("should return an error when given a custom header that cannot be marshalled", func(t *testing.T) {
		token, err := SignHMAC(secret, WithHeader("foo", func() {}))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal jwt headers")
		assert.Equal(t, "", token)
	})

	t.Run("should handle the iss claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithIss(iss))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the sub claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithSub(sub))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the aud claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithAud(aud))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the exp claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithExp(time.Unix(exp, 0)))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the nbf claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithNbf(time.Unix(nbf, 0)))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the iat claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithIat(time.Unix(iat, 0)))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle the jti claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithJti(jti))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom object claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", Foo{Name: "foobarbaz"}))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom array of strings claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", []string{"foo", "bar", "baz"}))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom array of ints claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", []int{1, 2, 3}))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom array of objects claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", []Foo{
			{Name: "foo"},
			{Name: "bar"},
			{Name: "baz"},
		}))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom bool claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", true))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom string claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", "foobarbaz"))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a custom int claim", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", 123))
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should return an error when given a custom claim that cannot be marshalled", func(t *testing.T) {
		token, err := SignHMAC(secret, WithClaim("foo", func() {}))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal jwt claims")
		assert.Equal(t, "", token)
	})
}

func TestVerifyHMAC(t *testing.T) {
	t.Parallel()

	t.Run("should verify all of the passed in standard claims and succeed if they are correct", func(t *testing.T) {
		testExp := time.Now().Add(30 * time.Second)
		testIat := time.Now()
		testNbf := time.Now()
		customHeaderKey := "foo"
		customHeaderVal := "FOO"
		customClaimKey := "bar"
		customClaimVal := "BAR"
		token, err := SignHMAC(
			secret,
			WithAud(aud),
			WithIss(iss),
			WithSub(sub),
			WithExp(testExp),
			WithNbf(testNbf),
			WithHeader(customHeaderKey, customHeaderVal),
			WithClaim(customClaimKey, customClaimVal),
			WithIat(testIat),
			WithJti(jti),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyAud(aud),
			VerifyIss(iss),
			VerifySub(sub),
			VerifyExp(5*time.Second),
			VerifyNbf(5*time.Second),
			VerifyHeaderEquals(customHeaderKey, customHeaderVal),
			VerifyClaimEquals(customClaimKey, customClaimVal),
		)
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, "HS256", decoded.GetAlg())
		assert.Equal(t, "JWT", decoded.GetType())
		assert.Equal(t, aud, decoded.GetAud())
		assert.Equal(t, iss, decoded.GetIss())
		assert.Equal(t, sub, decoded.GetSub())
		assert.Equal(t, testExp.Unix(), decoded.GetExp())
		assert.Equal(t, testNbf.Unix(), decoded.GetNbf())
		assert.Equal(t, customHeaderVal, decoded.Headers[customHeaderKey])
		assert.Equal(t, customClaimVal, decoded.Claims[customClaimKey])
		assert.Equal(t, testIat.Unix(), decoded.GetIat())
		assert.Equal(t, jti, decoded.GetJti())
	})

	t.Run("should return an error if the audience did not match", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithAud(aud),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyAud("WRONG-"+aud),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "aud")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the issuer did not match", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithIss("WRONG-"+iss),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyIss(iss),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "iss")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the subject did not match", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithSub("WRONG-"+sub),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifySub(sub),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "sub")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the expiry has passed", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithExp(time.Now().Add(-5*time.Minute)),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyExp(30*time.Second),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "exp")
		assert.Nil(t, decoded)
	})

	t.Run("should not error and return the decoded jwt if the expiry has passed but is within the clock skew", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithExp(time.Now().Add(-5*time.Second)),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyExp(30*time.Second),
		)
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
	})

	t.Run("should handle expiry not being a number", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithClaim("exp", "WRONG"),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyExp(30*time.Second),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "exp")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the not-before has not passed yet", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithNbf(time.Now().Add(5*time.Minute)),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyNbf(30*time.Second),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "nbf")
		assert.Nil(t, decoded)
	})

	t.Run("should not error and return the decoded jwt if the not-before has not passed yet but is within the clock skew", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithNbf(time.Now().Add(5*time.Second)),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyNbf(30*time.Second),
		)
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
	})

	t.Run("should handle not-before not being a number", func(t *testing.T) {
		token, err := SignHMAC(
			secret,
			WithClaim("nbf", "WRONG"),
		)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(
			secret,
			token,
			VerifyNbf(30*time.Second),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "nbf")
		assert.Nil(t, decoded)
	})

	t.Run("should handle malformed jwts", func(t *testing.T) {
		inputs := []string{
			"headers",
			"headers.",
			"headers.claims",
			"headers.claims.signature.",
			"headers.claims.signature.extra",
		}
		for _, input := range inputs {
			decoded, err := VerifyHMAC(secret, input)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "malformed")
			assert.Nil(t, decoded)
		}
	})

	t.Run("should handle malformed headers", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		tokenParts := strings.Split(token, ".")
		decoded, err := VerifyHMAC(secret, fmt.Sprintf("garbage.%s.%s", tokenParts[1], tokenParts[2]))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
		assert.Contains(t, err.Error(), "headers")
		assert.Nil(t, decoded)
	})

	t.Run("should handle malformed claims", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		tokenParts := strings.Split(token, ".")
		newPayload := fmt.Sprintf("%s.garbage", tokenParts[0])
		newSig := signHMAC(secret, newPayload)
		decoded, err := VerifyHMAC(secret, fmt.Sprintf("%s.%s", newPayload, newSig))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
		assert.Contains(t, err.Error(), "claims")
		assert.Nil(t, decoded)
	})

	t.Run("should handle invalid signature", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		tokenParts := strings.Split(token, ".")
		decoded, err := VerifyHMAC(secret, fmt.Sprintf("%s.%s.garbage", tokenParts[0], tokenParts[1]))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "signature")
		assert.Nil(t, decoded)
	})

	t.Run("should handle wrong secret", func(t *testing.T) {
		token, err := SignHMAC("WRONG-" + secret)
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "signature")
		assert.Nil(t, decoded)
	})

	t.Run("should reject unsupported algorithms", func(t *testing.T) {
		inputs := []string{
			"none",
			// HS256 - supported
			"HS384",
			"HS512",
			"RS256",
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
		}
		for _, input := range inputs {
			token, err := SignHMAC(secret, WithHeader("alg", input))
			assert.Nil(t, err)
			decoded, err := VerifyHMAC(secret, token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "alg")
			assert.Contains(t, err.Error(), "signature")
			assert.Contains(t, err.Error(), "not supported")
			assert.Nil(t, decoded)
		}
	})

	t.Run("should reject unsupported types", func(t *testing.T) {
		token, err := SignHMAC(secret, WithHeader("typ", "WRONG"))
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "jwt type")
		assert.Contains(t, err.Error(), "not supported")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the custom header did not match", func(t *testing.T) {
		customHeaderKey := "foo"
		customHeaderVal := "FOO"
		token, err := SignHMAC(secret, WithHeader(customHeaderKey, "WRONG-"+customHeaderVal))
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token, VerifyHeaderEquals(customHeaderKey, customHeaderVal))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "header")
		assert.Nil(t, decoded)
	})

	t.Run("should return an error if the custom claim did not match", func(t *testing.T) {
		customClaimKey := "foo"
		customClaimVal := "FOO"
		token, err := SignHMAC(secret, WithClaim(customClaimKey, "WRONG-"+customClaimVal))
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token, VerifyClaimEquals(customClaimKey, customClaimVal))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "claim")
		assert.Nil(t, decoded)
	})

	t.Run("should respect custom jwt validation functions", func(t *testing.T) {
		customHeaderKey := "foo"
		customHeaderVal := "FOO"
		customClaimsKey := "bar"
		customClaimsVal := "BAR"
		token, err := SignHMAC(secret, func(j *JWTOptions) {
			j.Headers[customHeaderKey] = customHeaderVal
			j.Claims[customClaimsKey] = customClaimsVal
		})
		assert.Nil(t, err)
		decoded, err := VerifyHMAC(secret, token, func(j *JWTDecoded) error {
			actualHeader := j.Headers[customHeaderKey]
			if actualHeader != customHeaderVal {
				return fmt.Errorf("custom header did not match: headers[%s] was %s instead of %s", customHeaderKey, actualHeader, customHeaderVal)
			}
			actualClaim := j.Claims[customClaimsKey]
			if actualClaim != customClaimsVal {
				return fmt.Errorf("custom claim did not match: claims[%s] was %s instead of %s", customClaimsKey, actualClaim, customClaimsVal)
			}
			return nil
		})
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, customHeaderVal, decoded.Headers[customHeaderKey])
		assert.Equal(t, customClaimsVal, decoded.Claims[customClaimsKey])
	})

	t.Run("should return an error if a custom jwt validation returns an error", func(t *testing.T) {
		token, err := SignHMAC(secret)
		assert.Nil(t, err)
		mockErr := fmt.Errorf("unit-test-simulate-failure")
		decoded, err := VerifyHMAC(secret, token, func(j *JWTDecoded) error {
			return mockErr
		})
		assert.ErrorIs(t, err, mockErr)
		assert.Nil(t, decoded)
	})
}

func TestSignRSA(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should produce an empty claim jwt", func(t *testing.T) {
		token, err := SignRSA(key)
		assert.Nil(t, err)
		assert.Regexp(t, jwtRegex, token)
	})

	t.Run("should handle a nil being passed in for the key", func(t *testing.T) {
		token, err := SignRSA(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "nil")
		assert.Equal(t, "", token)
	})

	t.Run("should return an error when given a custom header that cannot be marshalled", func(t *testing.T) {
		token, err := SignRSA(key, WithHeader("foo", func() {}))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal jwt headers")
		assert.Equal(t, "", token)
	})
}

func TestVerifyRSA(t *testing.T) {
	t.Parallel()

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should verify all of the passed in standard claims and succeed if they are correct", func(t *testing.T) {
		testExp := time.Now().Add(30 * time.Second)
		testIat := time.Now()
		testNbf := time.Now()
		customHeaderKey := "foo"
		customHeaderVal := "FOO"
		customClaimKey := "bar"
		customClaimVal := "BAR"
		token, err := SignRSA(
			key1,
			WithAud(aud),
			WithIss(iss),
			WithSub(sub),
			WithExp(testExp),
			WithNbf(testNbf),
			WithHeader(customHeaderKey, customHeaderVal),
			WithClaim(customClaimKey, customClaimVal),
			WithIat(testIat),
			WithJti(jti),
		)
		assert.Nil(t, err)
		decoded, err := VerifyRSA(
			&key1.PublicKey,
			token,
			VerifyAud(aud),
			VerifyIss(iss),
			VerifySub(sub),
			VerifyExp(5*time.Second),
			VerifyNbf(5*time.Second),
			VerifyHeaderEquals(customHeaderKey, customHeaderVal),
			VerifyClaimEquals(customClaimKey, customClaimVal),
		)
		assert.Nil(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, "RS256", decoded.GetAlg())
		assert.Equal(t, "JWT", decoded.GetType())
		assert.Equal(t, aud, decoded.GetAud())
		assert.Equal(t, iss, decoded.GetIss())
		assert.Equal(t, sub, decoded.GetSub())
		assert.Equal(t, testExp.Unix(), decoded.GetExp())
		assert.Equal(t, testNbf.Unix(), decoded.GetNbf())
		assert.Equal(t, customHeaderVal, decoded.Headers[customHeaderKey])
		assert.Equal(t, customClaimVal, decoded.Claims[customClaimKey])
		assert.Equal(t, testIat.Unix(), decoded.GetIat())
		assert.Equal(t, jti, decoded.GetJti())
	})

	t.Run("should handle malformed headers", func(t *testing.T) {
		token, err := SignRSA(key1)
		assert.Nil(t, err)
		tokenParts := strings.Split(token, ".")
		decoded, err := VerifyRSA(&key1.PublicKey, fmt.Sprintf("garbage.%s.%s", tokenParts[1], tokenParts[2]))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
		assert.Contains(t, err.Error(), "headers")
		assert.Nil(t, decoded)
	})

	t.Run("should handle invalid signature", func(t *testing.T) {
		token, err := SignRSA(key1)
		assert.Nil(t, err)
		tokenParts := strings.Split(token, ".")
		decoded, err := VerifyRSA(&key1.PublicKey, fmt.Sprintf("%s.%s.garbage", tokenParts[0], tokenParts[1]))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "signature")
		assert.Nil(t, decoded)
	})

	t.Run("should handle wrong key", func(t *testing.T) {
		token, err := SignRSA(key2)
		assert.Nil(t, err)
		decoded, err := VerifyRSA(&key1.PublicKey, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "signature")
		assert.Nil(t, decoded)
	})

	t.Run("should handle a nil being passed in for the key", func(t *testing.T) {
		token, err := SignRSA(key2)
		assert.Nil(t, err)
		decoded, err := VerifyRSA(nil, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "nil")
		assert.Nil(t, decoded)
	})

	t.Run("should reject unsupported algorithms", func(t *testing.T) {
		inputs := []string{
			"none",
			"HS256",
			"HS384",
			"HS512",
			// RS256 - supported
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
		}
		for _, input := range inputs {
			token, err := SignRSA(key1, WithHeader("alg", input))
			assert.Nil(t, err)
			decoded, err := VerifyRSA(&key1.PublicKey, token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "alg")
			assert.Contains(t, err.Error(), "signature")
			assert.Contains(t, err.Error(), "not supported")
			assert.Nil(t, decoded)
		}
	})

}
