package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"policy-engine/pkg/auth"
)

func newTestStore(t *testing.T) (*auth.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	store, err := auth.NewStore(mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, mr
}

func TestStore_ApproveAndLookup(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t)
	if err := store.Approve(ctx, "alice", "req-123", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := store.Lookup(ctx, "alice"); got != "req-123" {
		t.Errorf("Lookup: got %q want %q", got, "req-123")
	}
}

func TestStore_Revoke(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t)
	if err := store.Approve(ctx, "alice", "req-123", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if got := store.Lookup(ctx, "alice"); got != "" {
		t.Errorf("Lookup after Revoke: got %q want %q", got, "")
	}
}

func TestStore_TTLExpiry(t *testing.T) {
	ctx := context.Background()
	store, mr := newTestStore(t)
	if err := store.Approve(ctx, "alice", "req-123", time.Second); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Second)
	if got := store.Lookup(ctx, "alice"); got != "" {
		t.Errorf("Lookup after TTL expiry: got %q want %q", got, "")
	}
}

func TestStore_LookupMiss(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t)
	if got := store.Lookup(ctx, "nobody"); got != "" {
		t.Errorf("Lookup on missing key: got %q want %q", got, "")
	}
}

func TestStore_NewStore_Unreachable(t *testing.T) {
	_, err := auth.NewStore("localhost:1")
	if err == nil {
		t.Error("NewStore on unreachable Redis: expected error, got nil")
	}
}
