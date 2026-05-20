package audit

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/oschwald/maxminddb-golang"
)

var geoDB *maxminddb.Reader // nil if DB not available

func InitGeoIP(path string) {
	if path == "" {
		return
	}
	db, err := maxminddb.Open(path)
	if err == nil {
		geoDB = db
	}
}

func resolveGeo(ip string) GeoInfo {
	if geoDB == nil {
		return GeoInfo{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoInfo{}
	}
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Traits struct {
			ASN uint `maxminddb:"autonomous_system_number"`
		} `maxminddb:"traits"`
	}
	if err := geoDB.Lookup(parsed, &record); err != nil {
		return GeoInfo{}
	}
	return GeoInfo{Country: record.Country.ISOCode, ASN: record.Traits.ASN}
}

func extractIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
	return host
}

func hashToken(raw string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))[:16]
}

// Middleware captures every request as an AuditRecord.
func Middleware(sink *Sink, ch chan<- AuditRecord) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now().UTC()
		eventID := c.GetHeader("X-Request-ID")
		if eventID == "" {
			eventID = uuid.New().String()
		}
		ip := extractIP(c)

		c.Next() // run auth + handler

		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		rec := AuditRecord{
			EventID:      eventID,
			Ts:           start,
			SessionID:    c.GetString("session_id"),
			UserToken:    hashToken(raw),
			Sub:          c.GetString("sub"),
			SourceIP:     ip,
			SourceGeo:    resolveGeo(ip),
			Verb:         c.Request.Method,
			Endpoint:     c.FullPath(),
			ResponseCode: c.Writer.Status(),
			DurationMs:   time.Since(start).Milliseconds(),
			RequestRole:  c.GetString("request_role"),
		}

		if sink != nil {
			_ = sink.Write(rec)
		}
		if ch != nil {
			select {
			case ch <- rec:
			default: // drop if channel full - never block the request goroutine
			}
		}
	}
}
