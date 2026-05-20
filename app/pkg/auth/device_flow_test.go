package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"policy-engine/pkg/auth"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func stubKeycloak(t *testing.T, tokenStatus int, tokenBody map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protocol/openid-connect/auth/device":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "dev-code-123",
				"user_code":        "USER-CODE",
				"verification_uri": "http://localhost:8081/device",
				"expires_in":       600,
				"interval":         5,
			})
		case "/protocol/openid-connect/token":
			w.WriteHeader(tokenStatus)
			json.NewEncoder(w).Encode(tokenBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDeviceProxy_HandleDevice(t *testing.T) {
	stub := stubKeycloak(t, http.StatusOK, nil)
	proxy := auth.NewDeviceProxy(stub.URL, "test-client", "")

	router := gin.New()
	router.POST("/v1/auth/device", proxy.HandleDevice)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/device", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleDevice status: got %d want 200", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["device_code"] != "dev-code-123" {
		t.Errorf("device_code: got %v want dev-code-123", resp["device_code"])
	}
	if resp["user_code"] != "USER-CODE" {
		t.Errorf("user_code: got %v want USER-CODE", resp["user_code"])
	}
}

func TestDeviceProxy_HandleToken_Success(t *testing.T) {
	stub := stubKeycloak(t, http.StatusOK, map[string]any{
		"id_token":     "fake.id.token",
		"access_token": "fake.access.token",
		"expires_in":   3600,
	})
	proxy := auth.NewDeviceProxy(stub.URL, "test-client", "")

	router := gin.New()
	router.POST("/v1/auth/token", proxy.HandleToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token",
		strings.NewReader(`{"device_code":"dev-code-123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleToken status: got %d want 200", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["id_token"] != "fake.id.token" {
		t.Errorf("id_token: got %v want fake.id.token", resp["id_token"])
	}
}

func TestDeviceProxy_HandleToken_Pending(t *testing.T) {
	stub := stubKeycloak(t, http.StatusBadRequest, map[string]any{
		"error": "authorization_pending",
	})
	proxy := auth.NewDeviceProxy(stub.URL, "test-client", "")

	router := gin.New()
	router.POST("/v1/auth/token", proxy.HandleToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token",
		strings.NewReader(`{"device_code":"dev-code-123"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("HandleToken pending status: got %d want 400", w.Code)
	}
}

func TestDeviceProxy_HandleToken_BadRequest(t *testing.T) {
	stub := stubKeycloak(t, http.StatusOK, nil)
	proxy := auth.NewDeviceProxy(stub.URL, "test-client", "")

	router := gin.New()
	router.POST("/v1/auth/token", proxy.HandleToken)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token",
		strings.NewReader(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("HandleToken bad body status: got %d want 400", w.Code)
	}
}
