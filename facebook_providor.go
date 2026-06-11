package xsocial

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// FacebookProvider implements OAuth2 for Facebook
type FacebookProvider struct {
	*AbstractProvider

	// The base Facebook Graph URL
	graphURL string

	// The Graph API version for the request
	version string

	// The user fields being requested
	fields []string

	// Display the dialog in a popup view
	popup bool

	// Re-request a declined permission
	reRequest bool

	// The access token that was last used to retrieve a user
	lastToken string
}

// NewFacebookProvider creates a new Facebook provider instance
func NewFacebookProvider(config Config) ProviderInterface {
	provider := &FacebookProvider{
		AbstractProvider: NewAbstractProvider(
			nil,
			config.ClientID,
			config.ClientSecret,
			config.RedirectURL,
		),
		graphURL:  "https://graph.facebook.com",
		version:   "v23.0",
		fields:    []string{"name", "email", "gender", "verified", "link", "picture.width(1920)"},
		popup:     false,
		reRequest: false,
	}

	// Set the implementation reference
	provider.impl = provider

	// Set Facebook-specific defaults
	provider.scopes = []string{"email"}

	// Override with config scopes if provided
	if len(config.Scopes) > 0 {
		provider.scopes = config.Scopes
	}

	return provider
}

// GetAuthUrl gets the authentication URL for Facebook
func (p *FacebookProvider) GetAuthUrl(state string) string {
	return p.BuildAuthUrlFromBase(
		fmt.Sprintf("https://www.facebook.com/%s/dialog/oauth", p.version),
		state,
	)
}

// GetTokenUrl gets the token URL for Facebook
func (p *FacebookProvider) GetTokenUrl() string {
	return fmt.Sprintf("%s/%s/oauth/access_token", p.graphURL, p.version)
}

// GetAccessTokenResponse gets the access token response for the given code
func (p *FacebookProvider) GetAccessTokenResponse(code string) (map[string]any, error) {
	client := p.getHTTPClient()

	headers := p.getTokenHeaders(code)
	fields := p.getTokenFields(code)

	data := url.Values{}
	for k, v := range fields {
		data.Set(k, v)
	}

	req, err := http.NewRequest("POST", p.GetTokenUrl(), strings.NewReader(data.Encode()))
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// Facebook returns 'expires' instead of 'expires_in' sometimes
	if expires, ok := result["expires"]; ok {
		if _, hasExpiresIn := result["expires_in"]; !hasExpiresIn {
			result["expires_in"] = expires
		}
	}

	return result, nil
}

// GetUserByToken gets the user info for the given access token
func (p *FacebookProvider) GetUserByToken(token string) (map[string]any, error) {
	p.lastToken = token

	// Try to get user from OIDC token first
	user, err := p.getUserByOIDCToken(token)
	if err == nil && user != nil {
		return user, nil
	}

	// Fallback to access token
	return p.getUserFromAccessToken(token)
}

// MapUserToObject maps the raw user data to a User instance
func (p *FacebookProvider) MapUserToObject(user map[string]any) *User {
	var avatarURL string

	// Extract avatar from nested picture.data.url structure
	if picture, ok := user["picture"].(map[string]any); ok {
		if data, ok := picture["data"].(map[string]any); ok {
			avatarURL = getStringFromMap(data, "url")
		}
	}

	socialiteUser := NewUser()
	socialiteUser.AbstractUser = NewAbstractUser()
	socialiteUser.SetRaw(user)
	socialiteUser.Map(map[string]any{
		"id":              getStringFromMap(user, "id"),
		"nickname":        nil,
		"name":            getStringFromMap(user, "name"),
		"email":           getStringFromMap(user, "email"),
		"avatar":          avatarURL,
		"avatar_original": avatarURL,
		"profileUrl":      getStringFromMap(user, "link"),
	})

	return socialiteUser
}

// Fields sets the user fields to request from Facebook
func (p *FacebookProvider) Fields(fields []string) *FacebookProvider {
	p.fields = fields
	return p
}

// AsPopup sets the dialog to be displayed as a popup
func (p *FacebookProvider) AsPopup() *FacebookProvider {
	p.popup = true
	return p
}

// ReRequest re-requests permissions which were previously declined
func (p *FacebookProvider) ReRequest() *FacebookProvider {
	p.reRequest = true
	return p
}

// LastToken gets the last access token used
func (p *FacebookProvider) LastToken() string {
	return p.lastToken
}

// UsingGraphVersion specifies which graph version should be used
func (p *FacebookProvider) UsingGraphVersion(version string) *FacebookProvider {
	p.version = version
	return p
}

// BuildAuthUrlFromBase [Override] builds the authentication URL for the provider from the given base URL
func (p *FacebookProvider) BuildAuthUrlFromBase(baseURL, state string) string {
	params := p.getCodeFields(state)
	query := encodeQuery(params)
	return baseURL + "?" + query
}

// GetCodeFields [Override] gets the GET parameters for the code request
func (p *FacebookProvider) getCodeFields(state string) map[string]string {
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

	if p.popup {
		fields["display"] = "popup"
	}

	if p.reRequest {
		fields["auth_type"] = "rerequest"
	}

	maps.Copy(fields, p.parameters)

	return fields
}

// getUserByOIDCToken gets user data from Facebook OIDC token (JWT)
func (p *FacebookProvider) getUserByOIDCToken(token string) (map[string]any, error) {
	// Check if this looks like a JWT
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT token")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Get Facebook's JWKs for verification
	jwks, err := p.getFacebookJwks()
	if err != nil {
		return nil, fmt.Errorf("failed to get Facebook JWKs: %w", err)
	}

	// Find the matching key
	var matchingKey map[string]any
	if keys, ok := jwks["keys"].([]any); ok {
		for _, k := range keys {
			if key, ok := k.(map[string]any); ok {
				if keyID, ok := key["kid"].(string); ok && keyID == kid {
					matchingKey = key
					break
				}
			}
		}
	}

	if matchingKey == nil {
		return nil, fmt.Errorf("no matching key found in JWKs")
	}

	// Parse the token without full verification
	parser := jwt.NewParser()
	jwtToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	// Verify audience
	aud, ok := claims["aud"].(string)
	if !ok || aud != p.clientID {
		return nil, fmt.Errorf("token has incorrect audience")
	}

	// Verify issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss != "https://www.facebook.com" {
		return nil, fmt.Errorf("token has incorrect issuer")
	}

	// Convert claims to map[string]interface{}
	user := make(map[string]any)
	maps.Copy(user, claims)

	// Map standard OIDC fields to Facebook fields
	if sub, ok := user["sub"]; ok {
		user["id"] = sub
	}
	if givenName, ok := user["given_name"]; ok {
		user["first_name"] = givenName
	}
	if familyName, ok := user["family_name"]; ok {
		user["last_name"] = familyName
	}

	return user, nil
}

// getFacebookJwks gets Facebook's JSON Web Key Set for JWT verification
func (p *FacebookProvider) getFacebookJwks() (map[string]any, error) {
	client := p.getHTTPClient()

	resp, err := client.Get("https://limited.facebook.com/.well-known/oauth/openid/jwks/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get Facebook JWKs: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks map[string]any
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	return jwks, nil
}

// getUserFromAccessToken gets user data from Facebook access token
func (p *FacebookProvider) getUserFromAccessToken(token string) (map[string]any, error) {
	client := p.getHTTPClient()

	// Build query parameters
	params := url.Values{}
	params.Set("access_token", token)
	params.Set("fields", strings.Join(p.fields, ","))

	// Add appsecret_proof if client secret is available
	if p.clientSecret != "" {
		proof := p.generateAppSecretProof(token)
		params.Set("appsecret_proof", proof)
	}

	endpoint := fmt.Sprintf("%s/%s/me?%s", p.graphURL, p.version, params.Encode())

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user map[string]any
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return user, nil
}

// generateAppSecretProof generates the appsecret_proof for enhanced security
func (p *FacebookProvider) generateAppSecretProof(accessToken string) string {
	h := hmac.New(sha256.New, []byte(p.clientSecret))
	h.Write([]byte(accessToken))
	return fmt.Sprintf("%x", h.Sum(nil))
}
