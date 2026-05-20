package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"policy-engine/pkg/audit"
)

func TestSink_Write(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	sink, err := audit.NewSink(path)
	if err != nil {
		t.Fatal(err)
	}

	rec := audit.AuditRecord{
		EventID:      "test-id",
		Ts:           time.Now().UTC(),
		Sub:          "alice",
		SourceIP:     "1.2.3.4",
		Verb:         "POST",
		Endpoint:     "/request",
		ResponseCode: 202,
		DurationMs:   5,
	}
	if err := sink.Write(rec); err != nil {
		t.Fatal(err)
	}
	sink.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var got audit.AuditRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("bad JSON: %v - raw: %s", err, data)
	}
	if got.EventID != "test-id" {
		t.Fatalf("got event_id=%q, want test-id", got.EventID)
	}
	if got.Sub != "alice" {
		t.Fatalf("got sub=%q, want alice", got.Sub)
	}
	if got.ResponseCode != 202 {
		t.Fatalf("got response_code=%d, want 202", got.ResponseCode)
	}
}

func TestSink_MultipleWrites(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	path := f.Name()
	f.Close()

	sink, err := audit.NewSink(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		_ = sink.Write(audit.AuditRecord{
			EventID: fmt.Sprintf("ev-%d", i),
			Ts:      time.Now().UTC(),
		})
	}
	sink.Close()

	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
}
