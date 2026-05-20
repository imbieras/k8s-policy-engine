package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

type DeviceProxy struct {
	issuerURL       string
	clientID        string
	externalBaseURL string
	httpClient      *http.Client
}

func NewDeviceProxy(issuerURL, clientID, externalBaseURL string) *DeviceProxy {
	return &DeviceProxy{
		issuerURL:       issuerURL,
		clientID:        clientID,
		externalBaseURL: externalBaseURL,
		httpClient:      &http.Client{},
	}
}

func (p *DeviceProxy) HandleDevice(c *gin.Context) {
	form := url.Values{
		"client_id": {p.clientID},
		"scope":     {"openid email profile"},
	}
	resp, err := p.httpClient.Post(
		p.issuerURL+"/protocol/openid-connect/auth/device",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("keycloak: %v", err)})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Rewrite verification_uri so the browser uses the externally reachable address.
	if p.externalBaseURL != "" {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if uri, ok := m["verification_uri"].(string); ok {
				m["verification_uri"] = strings.Replace(uri, p.issuerURL, p.externalBaseURL, 1)
			}
			if uri, ok := m["verification_uri_complete"].(string); ok {
				m["verification_uri_complete"] = strings.Replace(uri, p.issuerURL, p.externalBaseURL, 1)
			}
			if rewritten, err := json.Marshal(m); err == nil {
				body = rewritten
			}
		}
	}

	c.Data(resp.StatusCode, "application/json", body)
}

func (p *DeviceProxy) HandleToken(c *gin.Context) {
	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	form := url.Values{
		"client_id":   {p.clientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {req.DeviceCode},
	}
	resp, err := p.httpClient.Post(
		p.issuerURL+"/protocol/openid-connect/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("keycloak: %v", err)})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}
