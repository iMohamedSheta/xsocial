# xsocial

A Go OAuth2 social authentication library supporting **Google**, **GitHub**, and **Facebook** — with Google Device Flow support. Inspired by Laravel Socialite.

## Installation

```bash
go get github.com/imohamedsheta/xsocial
```

## Supported Providers

| Provider | Default Scopes | Notes |
|----------|---------------|-------|
| `google` | `openid`, `profile`, `email` | Supports ID token (JWT) and access token |
| `github` | `user:email` | Fetches primary verified email |
| `facebook` | `email` | Supports OIDC token and access token |

---

## Quick Start

### 1. Create and configure the Socialite manager

```go
package main

import (
    "fmt"
    "github.com/imohamedsheta/xsocial"
)

func main() {
    s := xsocial.New()

    s.AddConfig("google", xsocial.Config{
        ClientID:     "your-google-client-id",
        ClientSecret: "your-google-client-secret",
        RedirectURL:  "https://yourapp.com/auth/google/callback",
    })

    s.AddConfig("github", xsocial.Config{
        ClientID:     "your-github-client-id",
        ClientSecret: "your-github-client-secret",
        RedirectURL:  "https://yourapp.com/auth/github/callback",
    })

    s.AddConfig("facebook", xsocial.Config{
        ClientID:     "your-facebook-app-id",
        ClientSecret: "your-facebook-app-secret",
        RedirectURL:  "https://yourapp.com/auth/facebook/callback",
    })
}
```

---

## Standard OAuth2 Flow

### Step 1 — Redirect the user

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    provider := s.Driver("google")

    // Optional: attach a session store for state/PKCE management
    provider.SetSessionStore(mySessionStore)

    // Get the redirect URL and send the user there
    redirectURL := provider.Redirect()
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

### Step 2 — Handle the callback

```go
func handleCallback(w http.ResponseWriter, r *http.Request) {
    provider := s.Driver("google")
    provider.SetRequest(r)
    provider.SetSessionStore(mySessionStore)

    user, err := provider.User()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Printf("ID:       %v\n", user.GetID())
    fmt.Printf("Name:     %s\n", user.GetName())
    fmt.Printf("Email:    %s\n", user.GetEmail())
    fmt.Printf("Avatar:   %s\n", user.GetAvatar())
    fmt.Printf("Token:    %s\n", user.Token)
}
```

---

## Stateless Mode

Skip session-based state validation (useful for APIs or SPAs):

```go
provider := s.Driver("github").Stateless()
redirectURL := provider.Redirect()
```

---

## PKCE Support

Enable Proof Key for Code Exchange for added security:

```go
provider := s.Driver("google")
provider.SetSessionStore(mySessionStore)
provider.EnablePKCE()
redirectURL := provider.Redirect()
```

---

## Custom Scopes

Override the default scopes for a provider:

```go
// Replace default scopes
provider := s.Driver("google").SetScopes([]string{"openid", "email"})

// Merge with default scopes
provider := s.Driver("google").Scopes([]string{"https://www.googleapis.com/auth/calendar"})
```

---

## Get User from an Existing Token

If you already have an access token (e.g. from a mobile client):

```go
provider := s.Driver("google")
user, err := provider.UserFromToken("ya29.existing-access-token")
if err != nil {
    log.Fatal(err)
}
fmt.Println(user.GetEmail())
```

---

## Token Refresh

```go
// AbstractProvider exposes RefreshToken — cast to access it
ap := s.Driver("google").(*xsocial.GoogleProvider) // or access via AbstractProvider
token, err := ap.RefreshToken("your-refresh-token")
if err != nil {
    log.Fatal(err)
}
fmt.Println("New access token:", token.AccessToken)
fmt.Println("Expires in:      ", token.ExpiresIn)
```

---

## Provider-Specific Options

### Facebook

```go
fbProvider := s.Driver("facebook").(*xsocial.FacebookProvider)

// Show the login dialog as a popup
fbProvider.AsPopup()

// Re-request a previously declined permission
fbProvider.ReRequest()

// Request specific Graph API fields
fbProvider.Fields([]string{"name", "email", "birthday"})

// Use a specific Graph API version
fbProvider.UsingGraphVersion("v18.0")
```

### GitHub

GitHub automatically fetches the primary verified email when the `user:email` scope is present (default).

---

## Google Device Flow

For TV / CLI apps that cannot open a browser:

```go
cfg := s.GetConfig("google")

flow := xsocial.NewGoogleDeviceFlow(
    cfg.ClientID,
    cfg.ClientSecret,
    []string{"openid", "profile", "email"},
)

// Step 1: request device code
authResp, err := flow.RequestDeviceCode()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Go to %s and enter code: %s\n", authResp.VerificationURL, authResp.UserCode)

// Step 2: poll until approved
for {
    time.Sleep(time.Duration(authResp.Interval) * time.Second)

    token, status, err := flow.PollForToken(authResp.DeviceCode)
    switch status {
    case xsocial.DeviceFlowPending:
        fmt.Println("Waiting for user approval…")
        continue
    case xsocial.DeviceFlowExpired:
        log.Fatal("Code expired")
    case xsocial.DeviceFlowDenied:
        log.Fatal("User denied access")
    case xsocial.DeviceFlowSuccess:
        userInfo, _ := flow.GetUserInfo(token.AccessToken)
        fmt.Println("Logged in as:", userInfo["name"])
        return
    default:
        log.Fatal(err)
    }
}
```

---

## Registering a Custom Provider

```go
s.Extend("twitter", func(config xsocial.Config) xsocial.ProviderInterface {
    return NewTwitterProvider(config)
})

s.AddConfig("twitter", xsocial.Config{
    ClientID:     "...",
    ClientSecret: "...",
    RedirectURL:  "https://yourapp.com/auth/twitter/callback",
})

provider := s.Driver("twitter")
```

---

## Session Store Interface

`xsocial` does not ship with a session implementation. Provide your own by implementing the `SessionStore` interface:

```go
type SessionStore interface {
    Put(key string, value string)
    Get(key string) string
    Pull(key string) string  // Get and delete in one call
}
```

A simple in-memory example for testing:

```go
type MemoryStore struct {
    data map[string]string
}

func NewMemoryStore() *MemoryStore {
    return &MemoryStore{data: make(map[string]string)}
}

func (m *MemoryStore) Put(key, value string) { m.data[key] = value }
func (m *MemoryStore) Get(key string) string  { return m.data[key] }
func (m *MemoryStore) Pull(key string) string {
    v := m.data[key]
    delete(m.data, key)
    return v
}
```

---

## User Fields Reference

| Method | Description |
|--------|-------------|
| `user.GetID()` | Provider-specific user ID |
| `user.GetName()` | Full display name |
| `user.GetEmail()` | Email address |
| `user.GetNickname()` | Username / handle |
| `user.GetAvatar()` | Profile picture URL |
| `user.GetRaw()` | Raw `map[string]any` from the provider |
| `user.Token` | Access token |
| `user.RefreshToken` | Refresh token |
| `user.ExpiresIn` | Token TTL in seconds |
| `user.ApprovedScopes` | Scopes granted by the user |

---

## License

MIT