package detector_test

import (
	"sort"
	"testing"
	"time"

	"policy-engine/pkg/detector"
)

func TestLatencyTracker_Empty(t *testing.T) {
	tr := detector.NewLatencyTracker(100)
	p50, p95, p99 := tr.Percentiles()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("empty tracker: got p50=%v p95=%v p99=%v, want all 0", p50, p95, p99)
	}
}

func TestLatencyTracker_Percentiles(t *testing.T) {
	tr := detector.NewLatencyTracker(1000)
	// Record 0..99 ms
	for i := 0; i < 100; i++ {
		tr.Record(time.Duration(i) * time.Millisecond)
	}
	p50, p95, p99 := tr.Percentiles()
	if p50 < 49*time.Millisecond || p50 > 51*time.Millisecond {
		t.Errorf("p50: got %v, want ~50ms", p50)
	}
	if p95 < 94*time.Millisecond || p95 > 96*time.Millisecond {
		t.Errorf("p95: got %v, want ~95ms", p95)
	}
	if p99 < 98*time.Millisecond || p99 > 100*time.Millisecond {
		t.Errorf("p99: got %v, want ~99ms", p99)
	}
}

func TestLatencyTracker_CircularOverwrite(t *testing.T) {
	cap := 10
	tr := detector.NewLatencyTracker(cap)
	// Fill with 0ms, then overwrite with 1ms×cap
	for i := 0; i < cap; i++ {
		tr.Record(0)
	}
	for i := 0; i < cap; i++ {
		tr.Record(time.Millisecond)
	}
	p50, _, _ := tr.Percentiles()
	if p50 != time.Millisecond {
		t.Errorf("after circular overwrite: p50=%v, want 1ms", p50)
	}
	_ = sort.Search // ensure sort is imported (used inside Percentiles)
}
