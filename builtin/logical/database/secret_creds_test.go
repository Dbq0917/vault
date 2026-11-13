// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"context"
	"sync"
	"testing"
	"time"

	v5 "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
	"github.com/stretchr/testify/require"
)

// closeTrackingDatabase is a mock v5 database that signals when Close is
// called and can delay UpdateUser to exercise lock contention between renew
// and revoke.
type closeTrackingDatabase struct {
	MockDatabaseV5
	closed          chan struct{}
	updateUserDelay time.Duration
}

func (d *closeTrackingDatabase) UpdateUser(ctx context.Context, req v5.UpdateUserRequest) (v5.UpdateUserResponse, error) {
	if d.updateUserDelay > 0 {
		time.Sleep(d.updateUserDelay)
	}
	return d.MockDatabaseV5.UpdateUser(ctx, req)
}

func (d *closeTrackingDatabase) Close() error {
	close(d.closed)
	return nil
}

type closeTrackingFactory struct {
	mu              sync.Mutex
	dbs             []*closeTrackingDatabase
	updateUserDelay time.Duration
}

func (f *closeTrackingFactory) new() (interface{}, error) {
	d := &closeTrackingDatabase{
		closed:          make(chan struct{}),
		updateUserDelay: f.updateUserDelay,
	}
	f.mu.Lock()
	f.dbs = append(f.dbs, d)
	f.mu.Unlock()
	return d, nil
}

func (f *closeTrackingFactory) instances() []*closeTrackingDatabase {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*closeTrackingDatabase(nil), f.dbs...)
}

func getDbBackendWithFactory(t *testing.T, factory func() (interface{}, error)) (*databaseBackend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.System = &systemViewWrapper{
		SystemView:     config.System,
		builtinFactory: factory,
	}
	config.StorageView = &logical.InmemStorage{}
	b := Backend(config)
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	b.schedule = &TestSchedule{}
	b.credRotationQueue = queue.New()
	b.populateQueue(context.Background(), config.StorageView)

	return b, config.StorageView
}

func writeDynamicRole(t *testing.T, b *databaseBackend, s logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   s,
		Data: map[string]interface{}{
			"db_name":     mockv5,
			"default_ttl": "1h",
			"max_ttl":     "2h",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func readCreds(t *testing.T, b *databaseBackend, s logical.Storage, role string) *logical.Response {
	t.Helper()
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	return resp
}

func credsSecret(username, role string) *logical.Secret {
	return &logical.Secret{
		InternalData: map[string]interface{}{
			"secret_type": "creds",
			"username":    username,
			"role":        role,
		},
		IssueTime: time.Now(),
	}
}

// TestBackend_RevokeRecyclesConnection verifies that revoking a leased
// credential removes the pooled connection and closes it, so physical
// sessions do not pile up on the database server, and that the next request
// lazily establishes a fresh connection.
func TestBackend_RevokeRecyclesConnection(t *testing.T) {
	factory := &closeTrackingFactory{}
	b, s := getDbBackendWithFactory(t, factory.new)
	defer b.Cleanup(context.Background())
	configureDBMount(t, s)
	writeDynamicRole(t, b, s, "test-role")

	creds := readCreds(t, b, s, "test-role")
	username := creds.Data["username"].(string)

	dbi := b.connections.Get(mockv5)
	require.NotNil(t, dbi, "expected a pooled connection after reading creds")
	require.Len(t, factory.instances(), 1)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   s,
		Secret:    credsSecret(username, "test-role"),
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	require.Eventually(t, func() bool {
		if b.connections.Get(mockv5) != nil {
			return false
		}
		select {
		case <-factory.instances()[0].closed:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "revoke should remove and close the pooled connection")

	// The next read lazily establishes a new connection.
	readCreds(t, b, s, "test-role")
	require.Eventually(t, func() bool {
		return len(factory.instances()) == 2 && b.connections.Get(mockv5) != nil
	}, 5*time.Second, 10*time.Millisecond, "expected a fresh connection after recycle")
}

// TestBackend_RenewRevokeConcurrentNoDeadlock runs renews and revokes
// concurrently while revoke recycles the pooled connection, verifying the
// lock interaction cannot deadlock.
func TestBackend_RenewRevokeConcurrentNoDeadlock(t *testing.T) {
	factory := &closeTrackingFactory{updateUserDelay: 5 * time.Millisecond}
	b, s := getDbBackendWithFactory(t, factory.new)
	defer b.Cleanup(context.Background())
	configureDBMount(t, s)
	writeDynamicRole(t, b, s, "test-role")

	creds := readCreds(t, b, s, "test-role")
	username := creds.Data["username"].(string)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					resp, err := b.HandleRequest(context.Background(), &logical.Request{
						Operation: logical.RenewOperation,
						Storage:   s,
						Secret:    credsSecret(username, "test-role"),
					})
					if err != nil || (resp != nil && resp.IsError()) {
						t.Errorf("renew failed: err:%v resp:%#v", err, resp)
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					resp, err := b.HandleRequest(context.Background(), &logical.Request{
						Operation: logical.RevokeOperation,
						Storage:   s,
						Secret:    credsSecret(username, "test-role"),
					})
					if err != nil || (resp != nil && resp.IsError()) {
						t.Errorf("revoke failed: err:%v resp:%#v", err, resp)
						return
					}
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent renew and revoke deadlocked")
	}
}
