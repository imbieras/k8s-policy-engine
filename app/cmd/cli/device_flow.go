package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const tokenFileSuffix = ".config/kubectl-access/token"

func tokenFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, tokenFileSuffix), nil
}

func login(serverURL string) error {
	resp, err := http.Post(serverURL+"/v1/auth/device", "application/json", nil)
	if err != nil {
		return fmt.Errorf("device authorization: %w", err)
	}
	defer resp.Body.Close()

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return fmt.Errorf("decode device response: %w", err)
	}

	if deviceResp.VerificationURIComplete != "" {
		fmt.Printf("Open this URL in your browser to authenticate:\n%s\n", deviceResp.VerificationURIComplete)
	} else {
		fmt.Printf("Open %s\nEnter code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)
	}

	interval := deviceResp.Interval
	if interval < 1 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		payload, _ := json.Marshal(map[string]string{"device_code": deviceResp.DeviceCode})
		tokenResp, err := http.Post(serverURL+"/v1/auth/token", "application/json", bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("token poll: %w", err)
		}
		body, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("decode token response: %w", err)
		}

		if errStr, ok := result["error"].(string); ok {
			if errStr == "authorization_pending" {
				continue
			}
			return fmt.Errorf("token error: %s", errStr)
		}

		idToken, _ := result["id_token"].(string)
		if idToken == "" {
			idToken, _ = result["access_token"].(string)
		}
		if idToken == "" {
			continue
		}

		path, err := tokenFilePath()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(idToken), 0600); err != nil {
			return fmt.Errorf("write token: %w", err)
		}
		fmt.Println("Logged in successfully.")
		return nil
	}

	return fmt.Errorf("device code expired")
}

func logout() error {
	path, err := tokenFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove token: %w", err)
	}
	fmt.Println("Logged out.")
	return nil
}

func whoami() error {
	token, err := loadStoredToken()
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("not logged in; run 'kubectl access login'")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode token payload: %w", err)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("parse token claims: %w", err)
	}

	fmt.Printf("sub: %s\nemail: %s\n", claims.Sub, claims.Email)
	return nil
}

func loadStoredToken() (string, error) {
	path, err := tokenFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
