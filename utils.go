package xsocial

import (
	"crypto/rand"
	"math/big"
	"net/url"
)

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func uniqueArray(arr []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, val := range arr {
		if !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}
	return result
}

func encodeQuery(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Add(k, v)
	}
	return values.Encode()
}

func getStringFromMap(m map[string]any, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getIntFromMap(m map[string]any, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

func getValueFromMap(m map[string]any, key string) any {
	if val, ok := m[key]; ok {
		return val
	}
	return nil
}

// getBoolFromMap safely gets a boolean value from a map
func getBoolFromMap(m map[string]any, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
