package workspace

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestWithSnapshotSharesImmutableCachedView(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	metadata, err := store.Import(ctx, demodata.ContosoHealth(), "prod")
	if err != nil {
		t.Fatal(err)
	}

	const readers = 24
	addresses := make(chan string, readers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if viewErr := store.WithSnapshot(ctx, metadata.ID, func(snapshot model.Snapshot) error {
				addresses <- fmt.Sprintf("%p", &snapshot.Resources[0])
				return nil
			}); viewErr != nil {
				addresses <- "error:" + viewErr.Error()
			}
		}()
	}
	close(start)
	wait.Wait()
	close(addresses)

	var first string
	for address := range addresses {
		if first == "" {
			first = address
		}
		if address != first {
			t.Fatalf("read-only views used different graph backing: first=%s got=%s", first, address)
		}
	}
}

func TestLeaderCancellationDoesNotCancelSharedSnapshotLoad(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	metadata, err := store.Import(ctx, demodata.ContosoHealth(), "prod")
	if err != nil {
		t.Fatal(err)
	}

	originalLoader := store.loadSnapshot
	started := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var calls atomic.Int32
	store.loadSnapshot = func(loadCtx context.Context, metadata SnapshotMetadata) (model.Snapshot, snapshotFileSignature, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return originalLoader(loadCtx, metadata)
		case <-loadCtx.Done():
			return model.Snapshot{}, snapshotFileSignature{}, loadCtx.Err()
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(ctx)
	leaderResult := make(chan error, 1)
	go func() {
		leaderResult <- store.WithSnapshot(leaderCtx, metadata.ID, func(model.Snapshot) error { return nil })
	}()
	<-started

	followerResult := make(chan error, 1)
	go func() {
		followerResult <- store.WithSnapshot(ctx, metadata.ID, func(snapshot model.Snapshot) error {
			if snapshot.ID != metadata.ID {
				return fmt.Errorf("snapshot id = %q, want %q", snapshot.ID, metadata.ID)
			}
			return nil
		})
	}()
	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context cancellation", err)
	}
	close(release)
	if err := <-followerResult; err != nil {
		t.Fatalf("follower inherited leader cancellation: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("snapshot decoded %d times, want one independent shared load", got)
	}
}
