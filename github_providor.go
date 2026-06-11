package xsocial

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// GitHubProvider implements OAuth2 for GitHub
type GitHubProvider struct {
	*AbstractProvider
}

// NewGitHubProvider creates a new GitHub provider instance
func NewGitHubProvider(config Config) ProviderInterface {
	provider := &GitHubProvider{
		AbstractProvider: NewAbstractProvider(
			nil,
			config.ClientID,
			config.ClientSecret,
			config.RedirectURL,
		),
	}

	// Set the implementation reference
	provider.impl = provider

	// Set GitHub-specific defaults
	provider.scopes = []string{"user:email"}

	// Override with config scopes if provided
	if len(config.Scopes) > 0 {
		provider.scopes = config.Scopes
	}

	return provider
}

// GetAuthUrl gets the authentication URL for GitHub
func (p *GitHubProvider) GetAuthUrl(state string) string {
	return p.BuildAuthUrlFromBase("https://github.com/login/oauth/authorize", state)
}

// GetTokenUrl gets the token URL for GitHub
func (p *GitHubProvider) GetTokenUrl() string {
	return "https://github.com/login/oauth/access_token"
}

// GetUserByToken gets the user info for the given access token
func (p *GitHubProvider) GetUserByToken(token string) (map[string]any, error) {
	client := p.getHTTPClient()

	// Get basic user info
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	p.setGitHubHeaders(req, token)

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

	// If user:email scope is requested, fetch the primary email
	if p.hasScopeInList("user:email") {
		email, err := p.getEmailByToken(token)
		if err == nil && email != "" {
			user["email"] = email
		}
	}

	return user, nil
}

// getEmailByToken gets the primary verified email for the given access token
func (p *GitHubProvider) getEmailByToken(token string) (string, error) {
	client := p.getHTTPClient()

	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	p.setGitHubHeaders(req, token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Don't fail if we can't get emails - just return empty
		return "", fmt.Errorf("failed to get user emails: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []map[string]any
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	// Find the primary verified email
	for _, email := range emails {
		isPrimary := getBoolFromMap(email, "primary")
		isVerified := getBoolFromMap(email, "verified")

		if isPrimary && isVerified {
			return getStringFromMap(email, "email"), nil
		}
	}

	return "", nil
}

// setGitHubHeaders sets the required headers for GitHub API requests
func (p *GitHubProvider) setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "token "+token)
}

// hasScopeInList checks if a specific scope is in the provider's scope list
func (p *GitHubProvider) hasScopeInList(scope string) bool {
	return slices.Contains(p.scopes, scope)
}

// MapUserToObject maps the raw user data to a User instance
func (p *GitHubProvider) MapUserToObject(user map[string]any) *User {
	avatarURL := getStringFromMap(user, "avatar_url")

	socialiteUser := NewUser()
	socialiteUser.AbstractUser = NewAbstractUser()
	socialiteUser.SetRaw(user)
	socialiteUser.Map(map[string]any{
		"id":       getValueFromMap(user, "id"),
		"nodeId":   getStringFromMap(user, "node_id"),
		"nickname": getStringFromMap(user, "login"),
		"name":     getStringFromMap(user, "name"),
		"email":    getStringFromMap(user, "email"),
		"avatar":   avatarURL,
	})

	return socialiteUser
}
