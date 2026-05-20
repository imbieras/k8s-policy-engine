package audit

import "time"

type GeoInfo struct {
	Country string `json:"country"` // ISO 3166-1 alpha-2, e.g. "LT"
	ASN     uint   `json:"asn"`
}

type AuditRecord struct {
	EventID      string    `json:"event_id"`
	Ts           time.Time `json:"ts"`
	SessionID    string    `json:"session_id,omitempty"`
	UserToken    string    `json:"user_token"`            // sha256(raw token)[:16], never raw
	Sub          string    `json:"sub"`                   // JWT subject / "anonymous"
	SourceIP     string    `json:"source_ip"`
	SourceGeo    GeoInfo   `json:"source_geo"`
	Verb         string    `json:"verb"`                  // HTTP method
	Endpoint     string    `json:"endpoint"`              // path, e.g. "/approve/abc"
	ResponseCode int       `json:"response_code"`
	DurationMs   int64     `json:"duration_ms"`
	RequestRole  string    `json:"request_role,omitempty"` // role from request body
	Label        string    `json:"label,omitempty"`        // filled offline by join.py
}
