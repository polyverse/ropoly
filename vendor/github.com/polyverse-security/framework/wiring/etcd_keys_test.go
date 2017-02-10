package wiring

import (
	"fmt"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
	"testing"
	"time"
)

func TestEtcdKeys(t *testing.T) { TestingT(t) }

type EtcdKeysBackendSuite struct {
}

var _ = Suite(&EtcdKeysBackendSuite{})

type EtcdClientCoreOSMock struct {
	values map[string]string
}

type TxnMock struct{}

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

func (mock EtcdClientCoreOSMock) Get(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.GetResponse, error) {
	if value, ok := mock.values[key]; ok {
		return &etcd.GetResponse{
			Kvs: []*mvccpb.KeyValue{
				&mvccpb.KeyValue{
					Key:   []byte(key),
					Value: []byte(value),
				},
			},
		}, nil
	} else {
		return nil, fmt.Errorf("No value for key: %s", key)
	}
}

func (e EtcdClientCoreOSMock) Put(ctx context.Context, key string, value string, opts ...etcd.OpOption) (*etcd.PutResponse, error) {
	return &etcd.PutResponse{}, nil
}

// Delete deletes a key, or optionally using WithRange(end), [key, end).
func (e EtcdClientCoreOSMock) Delete(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.DeleteResponse, error) {
	return &etcd.DeleteResponse{}, nil
}

// Compact compacts etcd KV history before the given rev.
func (e EtcdClientCoreOSMock) Compact(ctx context.Context, rev int64, opts ...etcd.CompactOption) (*etcd.CompactResponse, error) {
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
func (e EtcdClientCoreOSMock) Do(ctx context.Context, op etcd.Op) (etcd.OpResponse, error) {
	return etcd.OpResponse{}, nil
}

// Txn creates a transaction.
func (e EtcdClientCoreOSMock) Txn(ctx context.Context) etcd.Txn {
	return TxnMock{}
}

// Grant creates a new lease.
func (e EtcdClientCoreOSMock) Grant(ctx context.Context, ttl int64) (*etcd.LeaseGrantResponse, error) {
	return &etcd.LeaseGrantResponse{}, nil
}

// Revoke revokes the given lease.
func (e EtcdClientCoreOSMock) Revoke(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseRevokeResponse, error) {
	return &etcd.LeaseRevokeResponse{}, nil
}

// TimeToLive retrieves the lease information of the given lease ID.
func (e EtcdClientCoreOSMock) TimeToLive(ctx context.Context, id etcd.LeaseID, opts ...etcd.LeaseOption) (*etcd.LeaseTimeToLiveResponse, error) {
	return &etcd.LeaseTimeToLiveResponse{}, nil
}

// KeepAlive keeps the given lease alive forever.
func (e EtcdClientCoreOSMock) KeepAlive(ctx context.Context, id etcd.LeaseID) (<-chan *etcd.LeaseKeepAliveResponse, error) {
	return make(<-chan *etcd.LeaseKeepAliveResponse), nil
}

// KeepAliveOnce renews the lease once. In most of the cases, Keepalive
// should be used instead of KeepAliveOnce.
func (e EtcdClientCoreOSMock) KeepAliveOnce(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseKeepAliveResponse, error) {
	return &etcd.LeaseKeepAliveResponse{}, nil
}

// Close releases all resources Lease keeps for efficient communication
// with the etcd server.
func (e EtcdClientCoreOSMock) Close() error {
	return nil
}

// MemberList lists the current cluster membership.
func (e EtcdClientCoreOSMock) MemberList(ctx context.Context) (*etcd.MemberListResponse, error) {
	return &etcd.MemberListResponse{}, nil
}

// MemberAdd adds a new member into the cluster.
func (e EtcdClientCoreOSMock) MemberAdd(ctx context.Context, peerAddrs []string) (*etcd.MemberAddResponse, error) {
	return &etcd.MemberAddResponse{}, nil
}

// MemberRemove removes an existing member from the cluster.
func (e EtcdClientCoreOSMock) MemberRemove(ctx context.Context, id uint64) (*etcd.MemberRemoveResponse, error) {
	return &etcd.MemberRemoveResponse{}, nil
}

// MemberUpdate updates the peer addresses of the member.
func (e EtcdClientCoreOSMock) MemberUpdate(ctx context.Context, id uint64, peerAddrs []string) (*etcd.MemberUpdateResponse, error) {
	return &etcd.MemberUpdateResponse{}, nil
}

func (b *EtcdKeysBackendSuite) SetUpTest(c *C) {
	SetEtcdKeyReadTimeout(time.Duration(1) * time.Second)
}

func (b *EtcdKeysBackendSuite) TestBasicKey(c *C) {
	k := newEtcdKey("/polyverse/config", "default", "Default usage info")
	c.Assert(k.Name(), Equals, "/polyverse/config")
	c.Assert(k.Description(), Equals, "Default usage info")
}

func (b *EtcdKeysBackendSuite) TestSubkeys(c *C) {
	k := newEtcdKey("/polyverse/config", "default", "")
	c.Assert(k.Name(), Equals, "/polyverse/config")

	k1 := k.NewSubKey("subkey1", "", "")
	c.Assert(k1.Name(), Equals, "/polyverse/config/subkey1")

	k2 := k1.NewSubKey("subkey2", "", "")
	c.Assert(k2.Name(), Equals, "/polyverse/config/subkey1/subkey2")

	c.Assert(len(k.SubKeys()), Equals, 1)
	c.Assert(k.SubKeys()[0], Equals, k1)

	c.Assert(len(k1.SubKeys()), Equals, 1)
	c.Assert(k1.SubKeys()[0], Equals, k2)
}

func (b *EtcdKeysBackendSuite) TestReadSuccess(c *C) {
	k := newEtcdKey("/polyverse/config", "default", "")
	c.Assert(k.Name(), Equals, "/polyverse/config")

	NewEtcdClientCoreOS = func() EtcdClientCoreOS {
		return &EtcdClientCoreOSMock{
			values: map[string]string{
				"/polyverse/config": "read_from_etcd",
			},
		}
	}

	val, err := k.StringValue()
	c.Assert(err, IsNil) //We want an error from etcd
	c.Assert(val, Equals, "read_from_etcd")
}

func (b *EtcdKeysBackendSuite) TestOverrides(c *C) {
	k := newEtcdKey("/polyverse/config", "default", "")
	c.Assert(k.Name(), Equals, "/polyverse/config")

	SetEtcdKeyOverrides(nil)
	SetEtcdKeyOverrides(map[string]string{
		"/polyverse/config": "overriddenValue",
	})

	NewEtcdClientCoreOS = func() EtcdClientCoreOS {
		return &EtcdClientCoreOSMock{
			values: map[string]string{},
		}
	}

	_, err := k.StringValue()
	c.Assert(err, NotNil) //We want an error from etcd

	val := k.StringValueWithFallback()
	c.Assert(val, Equals, "overriddenValue")
}

func (b *EtcdKeysBackendSuite) TestDefaults(c *C) {
	k := newEtcdKey("/polyverse/config", "default", "")
	c.Assert(k.Name(), Equals, "/polyverse/config")

	SetEtcdKeyOverrides(nil)

	NewEtcdClientCoreOS = func() EtcdClientCoreOS {
		return &EtcdClientCoreOSMock{
			values: map[string]string{},
		}
	}

	_, err := k.StringValue()
	c.Assert(err, NotNil) //We want an error from etcd

	val := k.StringValueWithFallback()
	c.Assert(val, Equals, "default")
}
