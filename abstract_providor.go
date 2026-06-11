package xsocial

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
)

// ProviderMustImpl defines the methods that must be implemented by each provider
type ProviderMustImpl interface {
	GetAuthUrl(state string) string
	GetTokenUrl() string
	GetUserByToken(token string) (map[string]any, error)
	MapUserToObject(user map[string]any) *User
}

// AbstractProvider implements the ProviderContract interface
type AbstractProvider struct {
	impl ProviderMustImpl
	// The HTTP request instance
	request *http.Request

	// The HTTP Client instance
	httpClient *http.Client

	// The client ID
	clientID string

	// The client secret
	clientSecret string

	// The redirect URL
	redirectURL string

	// The custom parameters to be sent with the request
	parameters map[string]string

	// The scopes being requested
	scopes []string

	// The separating character for the requested scopes
	scopeSeparator string

	// Indicates if the session state should be utilized
	stateless bool

	// Indicates if PKCE should be used
	usesPKCE bool

	// The cached user instance
	user *User

	// Session storage for state and code_verifier
	sessionStore SessionStore
}

// SessionStore interface for managing session data
type SessionStore interface {
	Put(key string, value string)
	Get(key string) string
	Pull(key string) string
}

// NewAbstractProvider creates a new provider instance
func NewAbstractProvider(request *http.Request, clientID, clientSecret, redirectURL string) *AbstractProvider {
	return &AbstractProvider{
		request:        request,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURL:    redirectURL,
		parameters:     make(map[string]string),
		scopes:         []string{},
		scopeSeparator: ",",
		stateless:      false,
		usesPKCE:       false,
	}
}

// Redirect redirects the user of the application to the provider's authentication screen
func (p *AbstractProvider) Redirect() string {
	var state string

	if p.usesState() {
		state = p.GetState()
		if p.sessionStore != nil {
			p.sessionStore.Put("state", state)
		}
	}

	if p.usesPKCEMethod() {
		if p.sessionStore != nil {
			p.sessionStore.Put("code_verifier", p.getCodeVerifier())
		}
	}

	return p.impl.GetAuthUrl(state)
}

// BuildAuthUrlFromBase builds the authentication URL for the provider from the given base URL
func (p *AbstractProvider) BuildAuthUrlFromBase(baseURL, state string) string {
	params := p.getCodeFields(state)
	query := encodeQuery(params)
	return baseURL + "?" + query
}

// GetCodeFields gets the GET parameters for the code request
func (p *AbstractProvider) getCodeFields(state string) map[string]string {
	fields := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  p.redirectURL,
		"scope":         p.formatScopes(p.getScopes(), p.scopeSeparator),
		"response_type": "code",
	}

	if p.usesState() {
		fields["state"] = state
	}

	if p.usesPKCEMethod() {
		fields["code_challenge"] = p.getCodeChallenge()
		fields["code_challenge_method"] = p.getCodeChallengeMethod()
	}

	maps.Copy(fields, p.parameters)

	return fields
}

// FormatScopes formats the given scopes
func (p *AbstractProvider) formatScopes(scopes []string, scopeSeparator string) string {
	return strings.Join(scopes, scopeSeparator)
}

// User gets the user instance
func (p *AbstractProvider) User() (*User, error) {
	if p.user != nil {
		return p.user, nil
	}

	if p.hasInvalidState() {
		return nil, fmt.Errorf("invalid state")
	}

	response, err := p.GetAccessTokenResponse(p.getCode())
	if err != nil {
		return nil, err
	}

	accessToken := getStringFromMap(response, "access_token")
	user, err := p.impl.GetUserByToken(accessToken)
	if err != nil {
		return nil, err
	}

	return p.userInstance(response, user), nil
}

// UserInstance creates a user instance from the given data
func (p *AbstractProvider) userInstance(response map[string]any, user map[string]any) *User {
	p.user = p.impl.MapUserToObject(user)

	accessToken := getStringFromMap(response, "access_token")
	refreshToken := getStringFromMap(response, "refresh_token")
	expiresIn := getIntFromMap(response, "expires_in")
	scopeStr := getStringFromMap(response, "scope")

	var approvedScopes []string
	if scopeStr != "" {
		approvedScopes = strings.Split(scopeStr, p.scopeSeparator)
	} else {
		approvedScopes = []string{}
	}

	p.user.SetToken(accessToken)
	p.user.SetRefreshToken(refreshToken)
	p.user.SetExpiresIn(expiresIn)
	p.user.SetApprovedScopes(approvedScopes)

	return p.user
}

// UserFromToken gets a Social User instance from a known access token
func (p *AbstractProvider) UserFromToken(token string) (*User, error) {
	userData, err := p.impl.GetUserByToken(token)
	if err != nil {
		return nil, err
	}

	user := p.impl.MapUserToObject(userData)
	user.SetToken(token)

	return user, nil
}

// HasInvalidState determines if the current request / session has a mismatching "state"
func (p *AbstractProvider) hasInvalidState() bool {
	if p.isStateless() {
		return false
	}

	var state string
	if p.sessionStore != nil {
		state = p.sessionStore.Pull("state")
	}

	requestState := ""
	if p.request != nil {
		requestState = p.request.URL.Query().Get("state")
	}

	return state == "" || requestState != state
}

// GetAccessTokenResponse gets the access token response for the given code
func (p *AbstractProvider) GetAccessTokenResponse(code string) (map[string]any, error) {
	client := p.getHTTPClient()

	headers := p.getTokenHeaders(code)
	fields := p.getTokenFields(code)

	data := url.Values{}
	for k, v := range fields {
		data.Set(k, v)
	}

	req, err := http.NewRequest("POST", p.impl.GetTokenUrl(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAccessToken exchanges the given authorization code for an access token
func (p *AbstractProvider) GetAccessToken(code string) (string, error) {
	response, err := p.GetAccessTokenResponse(code)
	if err != nil {
		return "", err
	}

	accessToken, _ := response["access_token"].(string)
	if accessToken == "" {
		return "", fmt.Errorf("access token not found in response")
	}

	return accessToken, nil
}

// GetTokenHeaders gets the headers for the access token request
func (p *AbstractProvider) getTokenHeaders(code string) map[string]string {
	return map[string]string{
		"Accept": "application/json",
	}
}

// GetTokenFields gets the POST fields for the token request
func (p *AbstractProvider) getTokenFields(code string) map[string]string {
	fields := map[string]string{
		"grant_type":   "authorization_code",
		"client_id":    p.clientID,
		"code":         code,
		"redirect_uri": p.redirectURL,
	}

	if p.clientSecret != "" {
		fields["client_secret"] = p.clientSecret
	}

	if p.usesPKCEMethod() {
		if p.sessionStore != nil {
			verifier := p.sessionStore.Pull("code_verifier")
			if verifier != "" {
				fields["code_verifier"] = verifier
			}
		}
	}

	maps.Copy(fields, p.parameters)

	return fields
}

// RefreshToken refreshes a user's access token with a refresh token
func (p *AbstractProvider) RefreshToken(refreshToken string) (*Token, error) {
	response, err := p.getRefreshTokenResponse(refreshToken)
	if err != nil {
		return nil, err
	}

	accessToken := getStringFromMap(response, "access_token")
	newRefreshToken := getStringFromMap(response, "refresh_token")
	expiresIn := getIntFromMap(response, "expires_in")
	scopeStr := getStringFromMap(response, "scope")

	var approvedScopes []string
	if scopeStr != "" {
		approvedScopes = strings.Split(scopeStr, p.scopeSeparator)
	} else {
		approvedScopes = []string{}
	}

	return &Token{
		AccessToken:    accessToken,
		RefreshToken:   newRefreshToken,
		ExpiresIn:      expiresIn,
		ApprovedScopes: approvedScopes,
	}, nil
}

// GetRefreshTokenResponse gets the refresh token response for the given refresh token
func (p *AbstractProvider) getRefreshTokenResponse(refreshToken string) (map[string]any, error) {
	client := p.getHTTPClient()

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", p.clientID)

	if p.clientSecret != "" {
		data.Set("client_secret", p.clientSecret)
	}

	req, err := http.NewRequest("POST", p.impl.GetTokenUrl(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCode gets the code from the request
func (p *AbstractProvider) getCode() string {
	if p.request == nil {
		return ""
	}
	return p.request.URL.Query().Get("code")
}

// Scopes merges the scopes of the requested access
func (p *AbstractProvider) Scopes(scopes []string) ProviderInterface {
	p.scopes = uniqueArray(append(p.scopes, scopes...))
	return p
}

// SetScopes sets the scopes of the requested access
func (p *AbstractProvider) SetScopes(scopes []string) ProviderInterface {
	p.scopes = uniqueArray(scopes)
	return p
}

// GetScopes gets the current scopes
func (p *AbstractProvider) getScopes() []string {
	return p.scopes
}

// RedirectUrl sets the redirect URL
func (p *AbstractProvider) RedirectUrl(redirectURL string) ProviderInterface {
	p.redirectURL = redirectURL
	return p.impl.(ProviderInterface)
}

// GetHTTPClient gets an instance of the HTTP client
func (p *AbstractProvider) getHTTPClient() *http.Client {
	if p.httpClient == nil {
		p.httpClient = &http.Client{}
	}
	return p.httpClient
}

// SetHTTPClient sets the HTTP client instance
func (p *AbstractProvider) SetHTTPClient(client *http.Client) ProviderInterface {
	p.httpClient = client
	return p.impl.(ProviderInterface)
}

// SetRequest sets the request instance
func (p *AbstractProvider) SetRequest(request *http.Request) ProviderInterface {
	p.request = request
	return p.impl.(ProviderInterface)
}

// UsesState determines if the provider is operating with state
func (p *AbstractProvider) usesState() bool {
	return !p.stateless
}

// IsStateless determines if the provider is operating as stateless
func (p *AbstractProvider) isStateless() bool {
	return p.stateless
}

// Stateless indicates that the provider should operate as stateless
func (p *AbstractProvider) Stateless() ProviderInterface {
	p.stateless = true
	return p.impl.(ProviderInterface)
}

// GetState gets the string used for session state
func (p *AbstractProvider) GetState() string {
	return randomString(40)
}

// UsesPKCEMethod determines if the provider uses PKCE
func (p *AbstractProvider) usesPKCEMethod() bool {
	return p.usesPKCE
}

// EnablePKCE enables PKCE for the provider
func (p *AbstractProvider) EnablePKCE() ProviderInterface {
	p.usesPKCE = true
	return p.impl.(ProviderInterface)
}

// SetCodeVerifier sets the code verifier
func (p *AbstractProvider) SetCodeVerifier(verifier string) ProviderInterface {
	if p.sessionStore != nil {
		p.sessionStore.Put("code_verifier", verifier)
	}
	return p.impl.(ProviderInterface)
}

// GetCodeVerifier generates a random string of the right length for the PKCE code verifier
func (p *AbstractProvider) getCodeVerifier() string {
	return randomString(96)
}

// GetCodeChallenge generates the PKCE code challenge based on the PKCE code verifier in the session
func (p *AbstractProvider) getCodeChallenge() string {
	var codeVerifier string
	if p.sessionStore != nil {
		codeVerifier = p.sessionStore.Get("code_verifier")
	}

	hash := sha256.Sum256([]byte(codeVerifier))
	encoded := base64.StdEncoding.EncodeToString(hash[:])
	encoded = strings.TrimRight(encoded, "=")
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")

	return encoded
}

// GetCodeChallengeMethod returns the hash method used to calculate the PKCE code challenge
func (p *AbstractProvider) getCodeChallengeMethod() string {
	return "S256"
}

// With sets the custom parameters of the request
func (p *AbstractProvider) With(parameters map[string]string) ProviderInterface {
	p.parameters = parameters
	return p.impl.(ProviderInterface)
}

// SetSessionStore sets the session store instance
func (p *AbstractProvider) SetSessionStore(store SessionStore) ProviderInterface {
	p.sessionStore = store
	return p.impl.(ProviderInterface)
}
