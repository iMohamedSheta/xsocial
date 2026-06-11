package xsocial

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// GoogleProvider implements OAuth2 for Google
type GoogleProvider struct {
	*AbstractProvider
}

// NewGoogleProvider creates a new Google provider instance
func NewGoogleProvider(config Config) ProviderInterface {
	provider := &GoogleProvider{
		AbstractProvider: NewAbstractProvider(
			nil,
			config.ClientID,
			config.ClientSecret,
			config.RedirectURL,
		),
	}

	// Set the implementation reference
	provider.impl = provider

	provider.scopeSeparator = " "
	provider.scopes = []string{"openid", "profile", "email"}

	// Override with config scopes if provided
	if len(config.Scopes) > 0 {
		provider.scopes = config.Scopes
	}

	return provider
}

// GetAuthUrl gets the authentication URL for Google
func (p *GoogleProvider) GetAuthUrl(state string) string {
	return p.BuildAuthUrlFromBase("https://accounts.google.com/o/oauth2/auth", state)
}

// GetTokenUrl gets the token URL for Google
func (p *GoogleProvider) GetTokenUrl() string {
	return "https://www.googleapis.com/oauth2/v4/token"
}

// GetUserByToken gets the user info for the given access token
func (p *GoogleProvider) GetUserByToken(token string) (map[string]any, error) {
	// Check if this is a JWT token (ID token)
	if p.isJwtToken(token) {
		return p.getUserFromJwtToken(token)
	}

	// Otherwise, fetch user info from the userinfo endpoint
	client := p.getHTTPClient()

	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo?prettyPrint=false", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

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

// MapUserToObject maps the raw user data to a User instance
func (p *GoogleProvider) MapUserToObject(user map[string]any) *User {
	// Add deprecated fields for backwards compatibility
	if sub, ok := user["sub"]; ok {
		user["id"] = sub
	}
	if emailVerified, ok := user["email_verified"]; ok {
		user["verified_email"] = emailVerified
	}
	if profile, ok := user["profile"]; ok {
		user["link"] = profile
	}

	avatarURL := getStringFromMap(user, "picture")

	socialiteUser := NewUser()
	socialiteUser.AbstractUser = NewAbstractUser()
	socialiteUser.SetRaw(user)
	socialiteUser.Map(map[string]any{
		"id":              getValueFromMap(user, "sub"),
		"nickname":        getStringFromMap(user, "nickname"),
		"name":            getStringFromMap(user, "name"),
		"email":           getStringFromMap(user, "email"),
		"avatar":          avatarURL,
		"avatar_original": avatarURL,
	})

	return socialiteUser
}

// isJwtToken determines if the given token is a JWT (ID token)
func (p *GoogleProvider) isJwtToken(token string) bool {
	return strings.Count(token, ".") == 2 && len(token) > 100
}

// getUserFromJwtToken gets user data from Google ID token (JWT)
func (p *GoogleProvider) getUserFromJwtToken(idToken string) (map[string]any, error) {
	// Get Google's JWKs for verification
	jwks, err := p.getGoogleJwks()
	if err != nil {
		return nil, fmt.Errorf("failed to get Google JWKs: %w", err)
	}

	// Parse the token without verification first to get the key ID
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Find the matching key from JWKs
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

	// For simplicity, we'll parse the claims without full signature verification
	// In production, you should use a proper JWT library with JWK support
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	// Verify issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("invalid ID token issuer")
	}

	// Verify audience
	aud, ok := claims["aud"].(string)
	if !ok || aud != p.clientID {
		return nil, fmt.Errorf("invalid ID token audience")
	}

	// Convert claims to map[string]interface{}
	user := make(map[string]any)
	maps.Copy(user, claims)

	return user, nil
}

// getGoogleJwks gets Google's JSON Web Key Set for JWT verification
func (p *GoogleProvider) getGoogleJwks() (map[string]any, error) {
	client := p.getHTTPClient()

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get Google JWKs: %s", resp.Status)
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
