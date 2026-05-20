package detector

import (
	"log"
	"time"

	"policy-engine/pkg/audit"
)

// Reactor logs anomaly alerts for one model and tracks inference latency
type Reactor struct {
	name           string
	alertThreshold float32
	tracker        *LatencyTracker
	count          int64
}

func NewReactor(name string, alertT float32) *Reactor {
	return &Reactor{
		name:           name,
		alertThreshold: alertT,
		tracker:        NewLatencyTracker(1000),
	}
}

// Process records the inference latency, logs a percentile summary every 100 calls, and emits an ANOMALY ALERT log line if score >= alertThreshold.
func (r *Reactor) Process(score float32, lat time.Duration, rec audit.AuditRecord) {
	r.tracker.Record(lat)
	r.count++

	if r.count%100 == 0 {
		p50, p95, p99 := r.tracker.Percentiles()
		log.Printf("[%s] latency p50=%s p95=%s p99=%s (n=%d)",
			r.name, p50.Round(time.Microsecond),
			p95.Round(time.Microsecond), p99.Round(time.Microsecond), r.count)
	}

	if score >= r.alertThreshold {
		log.Printf("ANOMALY ALERT [%s] event=%s session=%s score=%.3f",
			r.name, rec.EventID, rec.SessionID, score)
	}
}
