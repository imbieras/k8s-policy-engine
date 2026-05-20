package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type Sink struct {
	mu  sync.Mutex
	bw  *bufio.Writer
	cls io.Closer
}

func NewSink(path string) (*Sink, error) {
	lj := &lumberjack.Logger{
		Filename: path,
		MaxSize:  100, // MB
		MaxAge:   7,   // days
		Compress: true,
	}
	return &Sink{bw: bufio.NewWriterSize(lj, 64*1024), cls: lj}, nil
}

func (s *Sink) Write(r AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.NewEncoder(s.bw).Encode(r); err != nil {
		return err
	}
	return s.bw.Flush()
}

func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.bw.Flush()
	return s.cls.Close()
}
