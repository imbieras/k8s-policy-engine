package audit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"policy-engine/pkg/audit"
)

func TestMiddleware_CapturesEventID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	records := make(chan audit.AuditRecord, 1)

	r := gin.New()
	r.Use(audit.Middleware(nil, records))
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-Request-ID", "req-123")
	req.Header.Set("X-Forwarded-For", "78.57.100.42")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	rec := <-records
	if rec.EventID != "req-123" {
		t.Errorf("event_id: got %q, want req-123", rec.EventID)
	}
	if rec.SourceIP != "78.57.100.42" {
		t.Errorf("source_ip: got %q, want 78.57.100.42", rec.SourceIP)
	}
	if rec.ResponseCode != 200 {
		t.Errorf("response_code: got %d, want 200", rec.ResponseCode)
	}
	if rec.Verb != "GET" {
		t.Errorf("verb: got %q, want GET", rec.Verb)
	}
}

func TestMiddleware_GeneratesEventIDWhenMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	records := make(chan audit.AuditRecord, 1)

	r := gin.New()
	r.Use(audit.Middleware(nil, records))
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	rec := <-records
	if rec.EventID == "" {
		t.Error("event_id should be generated when X-Request-ID header is missing")
	}
}

func TestMiddleware_Captures401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	records := make(chan audit.AuditRecord, 1)

	r := gin.New()
	r.Use(audit.Middleware(nil, records))
	r.GET("/secret", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	})

	req := httptest.NewRequest("GET", "/secret", nil)
	req.Header.Set("X-Request-ID", "unauth-evt")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	rec := <-records
	if rec.ResponseCode != 401 {
		t.Errorf("response_code: got %d, want 401", rec.ResponseCode)
	}
}

func TestMiddleware_DropsFull(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Channel with capacity 0 - middleware must not block
	records := make(chan audit.AuditRecord, 0)

	r := gin.New()
	r.Use(audit.Middleware(nil, records))
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		r.ServeHTTP(w, req)
		close(done)
	}()
	<-done // must complete without blocking
}
