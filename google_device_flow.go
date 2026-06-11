package xsocial

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	googleDeviceCodeURL = "https://oauth2.googleapis.com/device/code"
	googleTokenURL      = "https://oauth2.googleapis.com/token"

	// DeviceFlowPending means the user has not yet approved the request
	DeviceFlowPending = "pending"
	// DeviceFlowSuccess means the user approved and tokens were obtained
	DeviceFlowSuccess = "success"
	// DeviceFlowExpired means the device_code expired before the user approved
	DeviceFlowExpired = "expired"
	// DeviceFlowDenied means the user explicitly denied the request
	DeviceFlowDenied = "denied"
)

// DeviceAuthResponse is the response from the device authorization endpoint
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// DeviceTokenResponse holds the result of polling for a device token
type DeviceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`

	// Error fields (when polling returns an error)
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// GoogleDeviceFlow handles the Device Authorization Grant for Google OAuth
type GoogleDeviceFlow struct {
	clientID     string
	clientSecret string
	scopes       []string
	httpClient   *http.Client
}

// NewGoogleDeviceFlow creates a new GoogleDeviceFlow instance
func NewGoogleDeviceFlow(clientID, clientSecret string, scopes []string) *GoogleDeviceFlow {
	return &GoogleDeviceFlow{
		clientID:     clientID,
		clientSecret: clientSecret,
		scopes:       scopes,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// RequestDeviceCode initiates the device flow and returns the auth response
// containing the user_code to display and the device_code to poll with.
func (g *GoogleDeviceFlow) RequestDeviceCode() (*DeviceAuthResponse, error) {
	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("scope", strings.Join(g.scopes, " "))

	req, err := http.NewRequest("POST", googleDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (%s): %s", resp.Status, string(body))
	}

	var result DeviceAuthResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	// Default poll interval to 5 seconds if not specified
	if result.Interval == 0 {
		result.Interval = 5
	}

	return &result, nil
}

// PollForToken polls Google's token endpoint with the device_code.
// Returns:
//   - (token, DeviceFlowSuccess, nil) when the user approves
//   - (nil, DeviceFlowPending, nil) when still waiting
//   - (nil, DeviceFlowExpired, nil) when the code expired
//   - (nil, DeviceFlowDenied, nil) when the user denied
//   - (nil, "", error) on a real error
func (g *GoogleDeviceFlow) PollForToken(deviceCode string) (*DeviceTokenResponse, string, error) {
	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("client_secret", g.clientSecret)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequest("POST", googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create token poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("token poll request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read token poll response: %w", err)
	}

	var result DeviceTokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("failed to parse token poll response: %w", err)
	}

	// Check for known soft errors (not real failures)
	switch result.Error {
	case "":
		// No error — check we actually have an access token
		if result.AccessToken == "" {
			return nil, DeviceFlowPending, nil
		}
		return &result, DeviceFlowSuccess, nil

	case "authorization_pending":
		// User has not yet approved — keep polling
		return nil, DeviceFlowPending, nil

	case "slow_down":
		// We're polling too fast — still pending, caller should wait longer
		return nil, DeviceFlowPending, nil

	case "expired_token":
		return nil, DeviceFlowExpired, nil

	case "access_denied":
		return nil, DeviceFlowDenied, nil

	default:
		return nil, "", fmt.Errorf("token error (%s): %s", result.Error, result.ErrorDescription)
	}
}

// GetUserInfo fetches the Google user info using the obtained access token
func (g *GoogleDeviceFlow) GetUserInfo(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info (%s): %s", resp.Status, string(body))
	}

	var user map[string]any
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}
	return user, nil
}
