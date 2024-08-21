package dbsc

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	HeaderSecSessionRegistration = "Sec-Session-Registration"
	HeaderSecSessionChallenge    = "Sec-Session-Challenge"
	HeaderSecSessionID           = "Sec-Session-Id"
	HeaderSecSessionResponse     = "Sec-Session-Response"
)

var (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

type RegistrationClaims struct {
	Audience      string          `json:"aud"`
	Key           string          `json:"key"`
	Authorization string          `json:"authorization"`
	JWTID         string          `json:"jti"`
	IssuedAt      jwt.NumericDate `json:"iat"`
}

func (c RegistrationClaims) GetExpirationTime() (*jwt.NumericDate, error) {

}
func (c RegistrationClaims) GetIssuedAt() (*jwt.NumericDate, error) {

}
func (c RegistrationClaims) GetNotBefore() (*jwt.NumericDate, error) {

}
func (c RegistrationClaims) GetIssuer() (string, error) {

}
func (c RegistrationClaims) GetSubject() (string, error) {

}
func (c RegistrationClaims) GetAudience() (jwt.ClaimStrings, error) {

}

type ChallengeResponseClaims struct {
	// nonce
	JWTID    string `json:"jti"`
	Audience string `json:"aud"`
	// session ID
	Subject string `json:"sub"`
}

type CancelSessionResponse struct {
	SessionIdentifier string `json:"session_identifier"`
	Continue          bool   `json:"continue"`
}

type SessionRegistrationResponse struct {
	SessionIdentifier string       `json:"session_identifier"`
	RefreshURL        string       `json:"refresh_url"`
	Scope             Scope        `json:"scope"`
	Credentials       []Credential `json:"credentials"`
}

type Scope struct {
	Origin             string               `json:"origin"`
	IncludeSites       string               `json:"include_site"`
	DeferRequests      string               `json:"defer_requests"`
	ScopeSpecification []ScopeSpecification `json:"scope_specification"`
}

type ScopeSpecification struct {
	Type   string `json:"type"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

type Credential struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Attributes string `json:"attributes"`
}

type SessionRegistrationConfig struct {
	SupportedAlgorithms []string
	Path                string
	Challenge           string
	Authorization       string
}

func RegistrationHeader(cfg SessionRegistrationConfig) string {
	// TODO: escape qoutes?

	algos := strings.Join(cfg.SupportedAlgorithms, " ")

	value := fmt.Sprintf(`(%s);challenge="%s";path="%s"`, algos, cfg.Challenge, cfg.Path)

	if cfg.Authorization != "" {
		value += fmt.Sprintf(`;authorization="%s"`, cfg.Authorization)
	}

	return value
}

type ChallengeHeaderConfig struct {
	Challenge string
	SessionID string
}

func ChallengeHeader(cfg ChallengeHeaderConfig) string {
	return fmt.Sprintf(`session_id="%s",challenge="%s"`, cfg.SessionID, cfg.Challenge)
}

func ParseRegistrationJWT(token string) (*jwt.Token, error) {

	dbscKeyFunc := func(t *jwt.Token) (interface{}, error) {
		return []byte(t.Claims.(RegistrationClaims).Key), nil
	}

	return jwt.NewParser(
		jwt.WithValidMethods([]string{AlgES256, AlgRS256}),
		jwt.WithStrictDecoding(),
	).ParseWithClaims(token, &RegistrationClaims{}, dbscKeyFunc)
}
