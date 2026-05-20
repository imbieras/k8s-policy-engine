package detector

import (
	"fmt"
	"sort"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

func InitORT(libPath string) error {
	ort.SetSharedLibraryPath(libPath + "/libonnxruntime.so.1.20.1")
	if err := ort.InitializeEnvironment(); err != nil {
		return fmt.Errorf("ort init: %w", err)
	}
	return nil
}

func ShutdownORT() {
	ort.DestroyEnvironment()
}

type LatencyTracker struct {
	mu      sync.Mutex
	samples []time.Duration
	cap     int
	count   int64
}

func NewLatencyTracker(cap int) *LatencyTracker {
	return &LatencyTracker{samples: make([]time.Duration, cap), cap: cap}
}

func (t *LatencyTracker) Record(d time.Duration) {
	t.mu.Lock()
	t.samples[t.count%int64(t.cap)] = d
	t.count++
	t.mu.Unlock()
}

func (t *LatencyTracker) Percentiles() (p50, p95, p99 time.Duration) {
	t.mu.Lock()
	n := t.count
	if n == 0 {
		t.mu.Unlock()
		return 0, 0, 0
	}
	take := n
	if take > int64(t.cap) {
		take = int64(t.cap)
	}
	cp := make([]time.Duration, take)
	copy(cp, t.samples[:take])
	t.mu.Unlock()

	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	p50 = cp[take*50/100]
	p95 = cp[take*95/100]
	p99 = cp[take*99/100]
	return
}

type Scorer struct {
	session      *ort.AdvancedSession
	inputTensor  *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
}

func NewScorer(modelPath string) (*Scorer, error) {
	inputShape := ort.NewShape(1, int64(28))
	inputTensor, err := ort.NewEmptyTensor[float32](inputShape)
	if err != nil {
		return nil, fmt.Errorf("ort input tensor: %w", err)
	}

	outputShape := ort.NewShape(1, 2)
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return nil, fmt.Errorf("ort output tensor: %w", err)
	}

	sess, err := ort.NewAdvancedSession(modelPath,
		[]string{"input"}, []string{"probabilities"},
		[]ort.ArbitraryTensor{inputTensor},
		[]ort.ArbitraryTensor{outputTensor},
		nil)
	if err != nil {
		return nil, fmt.Errorf("ort session: %w", err)
	}
	return &Scorer{session: sess, inputTensor: inputTensor, outputTensor: outputTensor}, nil
}

// Score returns the anomaly probability and the time spent in session.Run.
func (s *Scorer) Score(fv FeatureVector) (float32, time.Duration, error) {
	copy(s.inputTensor.GetData(), fv.Slice())
	t0 := time.Now()
	if err := s.session.Run(); err != nil {
		return 0, 0, err
	}
	lat := time.Since(t0)
	return s.outputTensor.GetData()[1], lat, nil
}

func (s *Scorer) Close() {
	s.inputTensor.Destroy()
	s.outputTensor.Destroy()
	s.session.Destroy()
}
