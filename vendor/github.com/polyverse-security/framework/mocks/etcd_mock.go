package mocks

import (
	etcd "github.com/coreos/etcd/clientv3"
	fwiring "github.com/polyverse-security/framework/wiring"
	"golang.org/x/net/context"
)

type (
	EtcdMock    struct{}
	WatcherMock struct{}
	TxnMock     struct{}
)

func (e EtcdMock) Get(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.GetResponse, error) {
	return &etcd.GetResponse{}, nil
}

func (e EtcdMock) Put(ctx context.Context, key string, value string, opts ...etcd.OpOption) (*etcd.PutResponse, error) {
	return &etcd.PutResponse{}, nil
}

// Delete deletes a key, or optionally using WithRange(end), [key, end).
func (e EtcdMock) Delete(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.DeleteResponse, error) {
	return &etcd.DeleteResponse{}, nil
}

// Compact compacts etcd KV history before the given rev.
func (e EtcdMock) Compact(ctx context.Context, rev int64, opts ...etcd.CompactOption) (*etcd.CompactResponse, error) {
	return &etcd.CompactResponse{}, nil
}

// Do applies a single Op on KV without a transaction.
// Do is useful when declaring operations to be issued at a later time
// whereas Get/Put/Delete are for better suited for when the operation
// should be immediately issued at time of declaration.

// Do applies a single Op on KV without a transaction.
// Do is useful when creating arbitrary operations to be issued at a
// later time; the user can range over the operations, calling Do to
// execute them. Get/Put/Delete, on the other hand, are best suited
// for when the operation should be issued at the time of declaration.
func (e EtcdMock) Do(ctx context.Context, op etcd.Op) (etcd.OpResponse, error) {
	return etcd.OpResponse{}, nil
}

// Txn creates a transaction.
func (e EtcdMock) Txn(ctx context.Context) etcd.Txn {
	return TxnMock{}
}

// Grant creates a new lease.
func (e EtcdMock) Grant(ctx context.Context, ttl int64) (*etcd.LeaseGrantResponse, error) {
	return &etcd.LeaseGrantResponse{}, nil
}

// Revoke revokes the given lease.
func (e EtcdMock) Revoke(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseRevokeResponse, error) {
	return &etcd.LeaseRevokeResponse{}, nil
}

// TimeToLive retrieves the lease information of the given lease ID.
func (e EtcdMock) TimeToLive(ctx context.Context, id etcd.LeaseID, opts ...etcd.LeaseOption) (*etcd.LeaseTimeToLiveResponse, error) {
	return &etcd.LeaseTimeToLiveResponse{}, nil
}

// KeepAlive keeps the given lease alive forever.
func (e EtcdMock) KeepAlive(ctx context.Context, id etcd.LeaseID) (<-chan *etcd.LeaseKeepAliveResponse, error) {
	return make(<-chan *etcd.LeaseKeepAliveResponse), nil
}

// KeepAliveOnce renews the lease once. In most of the cases, Keepalive
// should be used instead of KeepAliveOnce.
func (e EtcdMock) KeepAliveOnce(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseKeepAliveResponse, error) {
	return &etcd.LeaseKeepAliveResponse{}, nil
}

// Close releases all resources Lease keeps for efficient communication
// with the etcd server.
func (e EtcdMock) Close() error {
	return nil
}

// MemberList lists the current cluster membership.
func (e EtcdMock) MemberList(ctx context.Context) (*etcd.MemberListResponse, error) {
	return &etcd.MemberListResponse{}, nil
}

// MemberAdd adds a new member into the cluster.
func (e EtcdMock) MemberAdd(ctx context.Context, peerAddrs []string) (*etcd.MemberAddResponse, error) {
	return &etcd.MemberAddResponse{}, nil
}

// MemberRemove removes an existing member from the cluster.
func (e EtcdMock) MemberRemove(ctx context.Context, id uint64) (*etcd.MemberRemoveResponse, error) {
	return &etcd.MemberRemoveResponse{}, nil
}

// MemberUpdate updates the peer addresses of the member.
func (e EtcdMock) MemberUpdate(ctx context.Context, id uint64, peerAddrs []string) (*etcd.MemberUpdateResponse, error) {
	return &etcd.MemberUpdateResponse{}, nil
}

// If takes a list of comparison. If all comparisons passed in succeed,
// the operations passed into Then() will be executed. Or the operations
// passed into Else() will be executed.
func (e TxnMock) If(cs ...etcd.Cmp) etcd.Txn {
	return e
}

// Then takes a list of operations. The Ops list will be executed, if the
// comparisons passed in If() succeed.
func (e TxnMock) Then(ops ...etcd.Op) etcd.Txn {
	return e
}

// Else takes a list of operations. The Ops list will be executed, if the
// comparisons passed in If() fail.
func (e TxnMock) Else(ops ...etcd.Op) etcd.Txn {
	return e
}

// Commit tries to commit the transaction.
func (e TxnMock) Commit() (*etcd.TxnResponse, error) {
	return &etcd.TxnResponse{}, nil
}

func EtcdMockFactory() fwiring.EtcdClientCoreOS {
	return &EtcdMock{}
}
