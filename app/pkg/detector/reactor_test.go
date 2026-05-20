package detector_test

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"policy-engine/pkg/audit"
	"policy-engine/pkg/detector"
)

func captureLog(fn func()) string {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

func TestReactor_NoAlertBelowThreshold(t *testing.T) {
	r := detector.NewReactor("XGB", 0.5)
	rec := audit.AuditRecord{EventID: "e1", SessionID: "sess-1", Ts: time.Now()}
	out := captureLog(func() {
		r.Process(0.3, time.Millisecond, rec)
	})
	if strings.Contains(out, "ANOMALY") {
		t.Fatalf("score=0.3 should not alert (threshold 0.5), got: %s", out)
	}
}

func TestReactor_AlertAboveThreshold(t *testing.T) {
	r := detector.NewReactor("XGB", 0.5)
	rec := audit.AuditRecord{EventID: "e2", SessionID: "sess-2", Ts: time.Now()}
	out := captureLog(func() {
		r.Process(0.7, time.Millisecond, rec)
	})
	if !strings.Contains(out, "ANOMALY ALERT [XGB]") {
		t.Fatalf("score=0.7 should alert, got: %s", out)
	}
	if !strings.Contains(out, "e2") {
		t.Fatalf("alert should include event ID e2, got: %s", out)
	}
}

func TestReactor_LatencyLogEvery100(t *testing.T) {
	r := detector.NewReactor("LGBM", 0.5)
	rec := audit.AuditRecord{EventID: "ex", Ts: time.Now()}
	var out string
	// Process 99 events - no latency log yet
	for i := 0; i < 99; i++ {
		r.Process(0.1, time.Millisecond, rec)
	}
	// 100th event should trigger latency log
	out = captureLog(func() {
		r.Process(0.1, time.Millisecond, rec)
	})
	if !strings.Contains(out, "[LGBM] latency") {
		t.Fatalf("100th inference should log latency, got: %s", out)
	}
}
