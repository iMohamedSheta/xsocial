package xsocial

import (
	"sync"
)

// Config holds OAuth provider configuration
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Socialite is the main manager implementation
type Socialite struct {
	mu        sync.RWMutex
	configs   map[string]Config
	factories map[string]ProviderFactory
}

// New creates a new Socialite manager
func New() *Socialite {
	s := &Socialite{
		configs:   make(map[string]Config),
		factories: make(map[string]ProviderFactory),
	}

	// Register default providers
	s.Extend("facebook", NewFacebookProvider)
	s.Extend("google", NewGoogleProvider)
	s.Extend("github", NewGitHubProvider)

	return s
}

// Extend registers a provider factory
func (s *Socialite) Extend(name string, factory ProviderFactory) SocialiteContract {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.factories[name] = factory
	return s
}

// AddConfig adds a provider configuration
func (s *Socialite) AddConfig(name string, config Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[name] = config
}

// Driver returns a provider by name
func (s *Socialite) Driver(driver ...string) ProviderInterface {
	name := ""
	if len(driver) > 0 {
		name = driver[0]
	} else {
		s.mu.RLock()
		for k := range s.configs {
			name = k
			break
		}
		s.mu.RUnlock()
	}

	s.mu.RLock()
	config, configExists := s.configs[name]
	factory, factoryExists := s.factories[name]
	s.mu.RUnlock()

	if !configExists || !factoryExists {
		return nil
	}

	return factory(config)
}

// GetConfig returns the configuration for the given provider name.
// Useful when you need the raw credentials (e.g. for the Device Authorization Grant).
func (s *Socialite) GetConfig(name string) Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configs[name]
}
