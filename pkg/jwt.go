package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type JWTHeaders map[string]any

type JWTClaims map[string]any

type JWTDecoded struct {
	Headers JWTHeaders
	Claims  JWTClaims
}

type JWTOptions struct {
	Headers JWTHeaders
	Claims  JWTClaims
}

const (
	stdHeaderAlg  = "alg"
	stdHeaderType = "typ"
	stdAlgHS256   = "HS256"
	stdTypeJWT    = "JWT"
	stdClaimAud   = "aud"
	stdClaimIss   = "iss"
	stdClaimSub   = "sub"
	stdClaimExp   = "exp"
	stdClaimNbf   = "nbf"
	stdClaimIat   = "iat"
	stdClaimJti   = "jti"
)

func SignHMAC(secret string, options ...func(*JWTOptions)) (string, error) {
	opts := &JWTOptions{
		Headers: map[string]any{
			stdHeaderAlg:  stdAlgHS256,
			stdHeaderType: stdTypeJWT,
		},
		Claims: map[string]any{},
	}
	for _, o := range options {
		o(opts)
	}
	headersStr, err := mapToJWTSegment(opts.Headers)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt headers: %w", err)
	}
	claimsStr, err := mapToJWTSegment(opts.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt claims: %w", err)
	}
	signature := sign(secret, fmt.Sprintf("%s.%s", headersStr, claimsStr))
	return fmt.Sprintf("%s.%s.%s", headersStr, claimsStr, signature), nil
}

func mapToJWTSegment(m map[string]any) (string, error) {
	bytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func sign(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	data := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(data)
}

func WithHeader(key string, val any) func(*JWTOptions) {
	return func(opts *JWTOptions) {
		opts.Headers[key] = val
	}
}

func WithClaim(key string, val any) func(*JWTOptions) {
	return func(opts *JWTOptions) {
		opts.Claims[key] = val
	}
}

func WithAud(val string) func(*JWTOptions) {
	return WithClaim(stdClaimAud, val)
}

func WithIss(val string) func(*JWTOptions) {
	return WithClaim(stdClaimIss, val)
}

func WithSub(val string) func(*JWTOptions) {
	return WithClaim(stdClaimSub, val)
}

func WithExp(val time.Time) func(*JWTOptions) {
	return WithClaim(stdClaimExp, val.Unix())
}

func WithNbf(val time.Time) func(*JWTOptions) {
	return WithClaim(stdClaimNbf, val.Unix())
}

func WithIat(val time.Time) func(*JWTOptions) {
	return WithClaim(stdClaimIat, val.Unix())
}

func WithJti(val string) func(*JWTOptions) {
	return WithClaim(stdClaimJti, val)
}

func VerifyHMAC(secret, token string, validations ...func(*JWTDecoded) error) (*JWTDecoded, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("jwt was malformed, expected 3 parts, found %d", len(segments))
	}
	headers, err := jwtSegmentToMap(segments[0])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt headers: %w", err)
	}
	if headers[stdHeaderType] != stdTypeJWT {
		return nil, fmt.Errorf("jwt type of '%s' is not supported", headers["typ"])
	}
	if headers[stdHeaderAlg] != stdAlgHS256 {
		return nil, fmt.Errorf("jwt signature alg of '%s' is not supported", headers["alg"])
	}
	if err := verify(secret, fmt.Sprintf("%s.%s", segments[0], segments[1]), segments[2]); err != nil {
		return nil, fmt.Errorf("jwt signature validation failed: %w", err)
	}
	claims, err := jwtSegmentToMap(segments[1])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt claims: %w", err)
	}
	decoded := JWTDecoded{
		Headers: headers,
		Claims:  claims,
	}
	for _, v := range validations {
		if err := v(&decoded); err != nil {
			return nil, err
		}
	}
	return &decoded, nil
}

func jwtSegmentToMap(s string) (map[string]any, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func verify(secret, payload, signature string) error {
	expected := sign(secret, payload)
	if expected != signature {
		return fmt.Errorf("signature did not match")
	}
	return nil
}

func VerifyHeaderEquals(key string, expected any) func(*JWTDecoded) error {
	return func(opts *JWTDecoded) error {
		actual := opts.Headers[key]
		if actual != expected {
			return fmt.Errorf("jwt failed header validation, (%s) '%v' was not equal to '%v'", key, actual, expected)
		}
		return nil
	}
}

func VerifyClaimEquals(key string, expected any) func(*JWTDecoded) error {
	return func(opts *JWTDecoded) error {
		actual := opts.Claims[key]
		if actual != expected {
			return fmt.Errorf("jwt failed claim validation, (%s) '%v' was not equal to '%v'", key, actual, expected)
		}
		return nil
	}
}

func VerifyClaimBefore(key string, expectedTime time.Time) func(*JWTDecoded) error {
	return func(opts *JWTDecoded) error {
		actualSeconds, expectedSeconds, err := prepareSecondsClaim(opts.Claims, key, expectedTime)
		if err != nil {
			return err
		}
		if actualSeconds > expectedSeconds {
			return fmt.Errorf("jwt failed claim validation, (%s) %v was not before %v", key, actualSeconds, expectedSeconds)
		}
		return nil
	}
}

func prepareSecondsClaim(claims JWTClaims, key string, expectedTime time.Time) (int64, int64, error) {
	val := claims[key]
	actualFloat, ok := val.(float64) // json unmarshals ints into floats
	if !ok {
		return 0, 0, fmt.Errorf("jwt failed claim validation, (%s) '%v' was not a number", key, val)
	}
	actualSeconds := int64(actualFloat)
	expectedSeconds := expectedTime.Unix()
	return actualSeconds, expectedSeconds, nil
}

func VerifyClaimAfter(key string, expectedTime time.Time) func(*JWTDecoded) error {
	return func(opts *JWTDecoded) error {
		actualSeconds, expectedSeconds, err := prepareSecondsClaim(opts.Claims, key, expectedTime)
		if err != nil {
			return err
		}
		if actualSeconds < expectedSeconds {
			return fmt.Errorf("jwt failed claim validation, (%s) %v was not after %v", key, actualSeconds, expectedSeconds)
		}
		return nil
	}
}

func VerifyAud(val string) func(*JWTDecoded) error {
	return VerifyClaimEquals(stdClaimAud, val)
}

func VerifyIss(val string) func(*JWTDecoded) error {
	return VerifyClaimEquals(stdClaimIss, val)
}

func VerifySub(val string) func(*JWTDecoded) error {
	return VerifyClaimEquals(stdClaimSub, val)
}

func VerifyExp(skew time.Duration) func(*JWTDecoded) error {
	return VerifyClaimAfter(stdClaimExp, time.Now().Add(-skew))
}

func VerifyNbf(skew time.Duration) func(*JWTDecoded) error {
	return VerifyClaimBefore(stdClaimNbf, time.Now().Add(skew))
}

func (j *JWTDecoded) GetAlg() string {
	return j.Headers.GetAlg()
}

func (j *JWTDecoded) GetType() string {
	return j.Headers.GetType()
}

func (j *JWTDecoded) GetAud() string {
	return j.Claims.GetAud()
}

func (j *JWTDecoded) GetIss() string {
	return j.Claims.GetIss()
}

func (j *JWTDecoded) GetSub() string {
	return j.Claims.GetSub()
}

func (j *JWTDecoded) GetExp() int64 {
	return j.Claims.GetExp()
}

func (j *JWTDecoded) GetNbf() int64 {
	return j.Claims.GetNbf()
}

func (j *JWTDecoded) GetIat() int64 {
	return j.Claims.GetIat()
}

func (j *JWTDecoded) GetJti() string {
	return j.Claims.GetJti()
}

func (h JWTHeaders) GetAlg() string {
	alg, _ := h[stdHeaderAlg].(string)
	return alg
}

func (h JWTHeaders) GetType() string {
	typ, _ := h[stdHeaderType].(string)
	return typ
}

func (c JWTClaims) GetAud() string {
	aud, _ := c[stdClaimAud].(string)
	return aud
}

func (c JWTClaims) GetIss() string {
	iss, _ := c[stdClaimIss].(string)
	return iss
}

func (c JWTClaims) GetSub() string {
	sub, _ := c[stdClaimSub].(string)
	return sub
}

func (c JWTClaims) GetExp() int64 {
	exp, _ := c[stdClaimExp].(float64) // json unmarshals ints into floats
	return int64(exp)
}

func (c JWTClaims) GetNbf() int64 {
	nbf, _ := c[stdClaimNbf].(float64) // json unmarshals ints into floats
	return int64(nbf)
}

func (c JWTClaims) GetIat() int64 {
	iat, _ := c[stdClaimIat].(float64) // json unmarshals ints into floats
	return int64(iat)
}

func (c JWTClaims) GetJti() string {
	jti, _ := c[stdClaimJti].(string)
	return jti
}
