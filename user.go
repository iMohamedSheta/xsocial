package xsocial

// Token represents an OAuth token
type Token struct {
	AccessToken    string   `json:"access_token"`
	RefreshToken   string   `json:"refresh_token"`
	ExpiresIn      int      `json:"expires_in"`
	ApprovedScopes []string `json:"approved_scopes"`
}

// User represents an OAuth2 authenticated user with token information
type User struct {
	// Embedded abstract user
	*AbstractUser

	// The user's access token
	Token string `json:"token"`

	// The refresh token that can be exchanged for a new access token
	RefreshToken string `json:"refresh_token"`

	// The number of seconds the access token is valid for
	ExpiresIn int `json:"expires_in"`

	// The scopes the user authorized. The approved scopes may be a subset of the requested scopes
	ApprovedScopes []string `json:"approved_scopes"`
}

// NewUser creates a new User instance
func NewUser() *User {
	return &User{
		ApprovedScopes: make([]string, 0),
	}
}

// SetToken sets the token on the user
func (u *User) SetToken(token string) *User {
	u.Token = token
	return u
}

// SetRefreshToken sets the refresh token required to obtain a new access token
func (u *User) SetRefreshToken(refreshToken string) *User {
	u.RefreshToken = refreshToken
	return u
}

// SetExpiresIn sets the number of seconds the access token is valid for
func (u *User) SetExpiresIn(expiresIn int) *User {
	u.ExpiresIn = expiresIn
	return u
}

// SetApprovedScopes sets the scopes that were approved by the user during authentication
func (u *User) SetApprovedScopes(approvedScopes []string) *User {
	u.ApprovedScopes = approvedScopes
	return u
}
