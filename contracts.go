package xsocial

import "net/http"

// SocialiteContract is the main interface for the Socialite manager
type SocialiteContract interface {
	Driver(driver ...string) ProviderInterface
	Extend(name string, factory ProviderFactory) SocialiteContract
}

// ProviderInterface defines the contract for OAuth providers
type ProviderInterface interface {
	Redirect() string
	User() (*User, error)
	UserFromToken(token string) (*User, error)
	SetScopes(scopes []string) ProviderInterface
	Scopes(scopes []string) ProviderInterface
	GetState() string
	With(parameters map[string]string) ProviderInterface
	SetRequest(r *http.Request) ProviderInterface
	Stateless() ProviderInterface
	EnablePKCE() ProviderInterface
	SetSessionStore(store SessionStore) ProviderInterface
	SetHTTPClient(client *http.Client) ProviderInterface
	RedirectUrl(url string) ProviderInterface
	SetCodeVerifier(verifier string) ProviderInterface
	GetAccessToken(code string) (string, error)
	GetAccessTokenResponse(code string) (map[string]any, error)
}

// ProviderFactory creates provider instances
type ProviderFactory func(config Config) ProviderInterface
