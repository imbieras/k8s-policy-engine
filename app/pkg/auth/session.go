package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
}

func NewStore(addr string) (*Store, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}
	return &Store{client: client}, nil
}

func (s *Store) Approve(ctx context.Context, sub, requestID string, ttl time.Duration) error {
	if err := s.client.Set(ctx, "sess:"+sub, requestID, ttl).Err(); err != nil {
		return fmt.Errorf("approve %s: %w", sub, err)
	}
	return nil
}

func (s *Store) Lookup(ctx context.Context, sub string) string {
	val, err := s.client.Get(ctx, "sess:"+sub).Result()
	if err != nil {
		return ""
	}
	return val
}

func (s *Store) Revoke(ctx context.Context, sub string) error {
	if err := s.client.Del(ctx, "sess:"+sub).Err(); err != nil {
		return fmt.Errorf("revoke %s: %w", sub, err)
	}
	// DEL on a missing key returns 0, nil - already-expired sessions are a no-op.
	return nil
}

func (s *Store) Close() error {
	return s.client.Close()
}
