package wiring

import (
	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/polyverse-security/framework/constants/components"
	fcontext "github.com/polyverse-security/framework/context"
	"golang.org/x/net/context"
	"reflect"
	"sync"
	"time"
)

type (
	EtcdClientCoreOS interface // http://play.golang.org/p/5zkJ1jTsJu
	{
		etcd.KV
		etcd.Lease
		etcd.Cluster
	}

	EtcdClientWatcher interface {
		etcd.Watcher
	}

	etcdClientWatcherFactory func(EtcdClientCoreOS) EtcdClientWatcher
	etcdCoreOSFactory        func() EtcdClientCoreOS
	etcdMachinesFactory      func() []string
)

var (
	cachedCoreOSClient  *etcdWrapper
	NewEtcdClientCoreOS etcdCoreOSFactory
	GetEtcdMachines     etcdMachinesFactory
	NewEtcdWatcher      etcdClientWatcherFactory
)

type etcdWrapper struct {
	updateMutex  sync.RWMutex
	actualClient *etcd.Client

	keepAlivesMutex sync.Mutex
	keepAlives      []etcd.LeaseID
}

func (e *etcdWrapper) ReplaceActualClient(c *etcd.Client) {
	e.updateMutex.Lock()
	defer e.updateMutex.Unlock()
	log.Info("Replaced the actual etcd client with a new one (presumably because of members update)")
	e.actualClient = c

	log.Infof("Replaying %d keepalives onto the new client, to ensure our leases to etcd don't expire.", len(e.keepAlives))
	e.keepAlivesMutex.Lock()
	defer e.keepAlivesMutex.Unlock()
	//replay all keepalives onto the new client.
	for _, lease := range e.keepAlives {
		e.actualClient.KeepAlive(fcontext.DefaultEtcdTimeout(), lease)
	}
}

func (e etcdWrapper) checkSafety() {
	if e.actualClient == nil {
		log.Fatal("Etcd Client wrapper has no actual client to connect to etcd with. This means it was not initialized correctly, or was Close()'d")
	}
}

func (e *etcdWrapper) Put(ctx context.Context, key, val string, opts ...etcd.OpOption) (*etcd.PutResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Put(ctx, key, val, opts...)
}

func (e *etcdWrapper) Get(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.GetResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Get(ctx, key, opts...)
}

func (e *etcdWrapper) Delete(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.DeleteResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Delete(ctx, key, opts...)
}

func (e *etcdWrapper) Compact(ctx context.Context, rev int64, opts ...etcd.CompactOption) (*etcd.CompactResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Compact(ctx, rev, opts...)
}

func (e *etcdWrapper) Do(ctx context.Context, op etcd.Op) (etcd.OpResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Do(ctx, op)
}

func (e *etcdWrapper) Txn(ctx context.Context) etcd.Txn {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Txn(ctx)
}

// Grant creates a new lease.
func (e *etcdWrapper) Grant(ctx context.Context, ttl int64) (*etcd.LeaseGrantResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Grant(ctx, ttl)
}

// Revoke revokes the given lease.
func (e *etcdWrapper) Revoke(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseRevokeResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.Revoke(ctx, id)
}

// KeepAlive keeps the given lease alive forever.
func (e *etcdWrapper) KeepAlive(ctx context.Context, id etcd.LeaseID) (<-chan *etcd.LeaseKeepAliveResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()

	e.keepAlivesMutex.Lock()
	defer e.keepAlivesMutex.Unlock()
	e.checkSafety()

	e.keepAlives = append(e.keepAlives, id)

	return e.actualClient.KeepAlive(ctx, id)
}

// KeepAliveOnce renews the lease once. In most of the cases, Keepalive
// should be used instead of KeepAliveOnce.
func (e *etcdWrapper) KeepAliveOnce(ctx context.Context, id etcd.LeaseID) (*etcd.LeaseKeepAliveResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.KeepAliveOnce(ctx, id)
}

// Close releases all resources Lease keeps for efficient communication
// with the etcd server.
func (e *etcdWrapper) Close() error {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	oldClient := e.actualClient
	e.actualClient = nil
	return oldClient.Close()
}

// MemberList lists the current cluster membership.
func (e *etcdWrapper) MemberList(ctx context.Context) (*etcd.MemberListResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.MemberList(ctx)
}

// MemberAdd adds a new member into the cluster.
func (e *etcdWrapper) MemberAdd(ctx context.Context, peerAddrs []string) (*etcd.MemberAddResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.MemberAdd(ctx, peerAddrs)
}

// MemberRemove removes an existing member from the cluster.
func (e *etcdWrapper) MemberRemove(ctx context.Context, id uint64) (*etcd.MemberRemoveResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.MemberRemove(ctx, id)
}

// MemberUpdate updates the peer addresses of the member.
func (e *etcdWrapper) MemberUpdate(ctx context.Context, id uint64, peerAddrs []string) (*etcd.MemberUpdateResponse, error) {
	e.updateMutex.RLock()
	defer e.updateMutex.RUnlock()
	e.checkSafety()
	return e.actualClient.MemberUpdate(ctx, id, peerAddrs)
}

func init() {
	NewEtcdClientCoreOS = newEtcdClientCoreOS
	GetEtcdMachines = defaultEtcdMachines
	NewEtcdWatcher = newEtcdClientWatcher

	go watchEtcdMemberUpdates()
}

func newEtcdClientCoreOS() EtcdClientCoreOS {
	if cachedCoreOSClient != nil {
		return cachedCoreOSClient
	}
	log.Info("Creating etcd client")

	cfg := etcd.Config{
		Endpoints: GetEtcdMachines(),
	}
	if c, err := etcd.New(cfg); err != nil {
		log.WithFields(log.Fields{"Error": err, "Config": cfg}).Fatal("Unable to launch an etcd client based on the expected Etcd Endpoints.")
		return nil
	} else {
		log.WithFields(log.Fields{"etcdClient": c}).Debug("Etcd client factory created a client")
		cachedCoreOSClient = &etcdWrapper{
			actualClient: c,
			updateMutex:  sync.RWMutex{},

			keepAlives:      []etcd.LeaseID{},
			keepAlivesMutex: sync.Mutex{},
		}
		return cachedCoreOSClient
	}
}

func newEtcdClientWatcher(client EtcdClientCoreOS) EtcdClientWatcher {
	if etcdClient, ok := client.(*etcdWrapper); ok {
		return etcd.NewWatcher(etcdClient.actualClient)
	} else {
		log.WithField("EtcdClientType", reflect.TypeOf(client)).Fatal("Unable to generate am Etcd Client Watcher from this etcd client type. Expected type: wiring.etcdWrapper")
		return nil
	}
}

func defaultEtcdMachines() []string {
	machines := []string{
		components.EtcdContainerPrefix + "_1:" + components.EtcdClientPort,
		components.EtcdContainerPrefix + "_2:" + components.EtcdClientPort,
	}
	log.WithField("EtcdMachines", machines).Info("List of Etcd Machines Requested.")
	return machines
}

func watchEtcdMemberUpdates() {
	log.Info("Started goroutine to watch member updates on etcd. This routine will replace the proc-wide client periodically (leaving the older client to be finalized later.)")
	for {
		log.Debug("Looking for current members in the etcd cluster....")
		ec := NewEtcdClientCoreOS()
		if membersList, err := ec.MemberList(fcontext.DefaultEtcdTimeout()); err != nil {
			log.WithField("Error", err).Error("An error occurred when retrieving members list of etcd cluster for updating endpoints.")
		} else if etcdStruct, ok := ec.(*etcd.Client); !ok {
			log.WithField("EtcdClientCoreOsType", reflect.TypeOf(ec)).Error("The etcd client implementation is not from the etcd library. Unable to periodically update members for this type. Aborting the periodic update goroutine....")
			return
		} else if len(membersList.Members) != len(etcdStruct.Endpoints()) {
			log.WithFields(log.Fields{"ClusterMembers": membersList.Members, "ClientEndpoints": etcdStruct.Endpoints()}).Info("The number of members in the cluster does not match the number of endpoints in our default client. Replacing this client with a new one (and let the current client get garbage-collected later...)")
			newEndpoints := []string{}
			for _, member := range membersList.Members {
				newEndpoints = append(newEndpoints, member.Name+":"+components.EtcdClientPort)
			}

			log.WithFields(log.Fields{"NewEndpoints": newEndpoints, "OldEndpoints": etcdStruct.Endpoints()}).Info("Updating the list of endpoints now...")

			cfg := etcd.Config{
				Endpoints: newEndpoints,
			}

			if newClient, err := etcd.New(cfg); err != nil {
				log.WithFields(log.Fields{"Error": err, "Config": cfg}).Error("Error occurred when attempting to create a new client with the specified endpoint configuration. Aborting client update. Preserving status quo.")
			} else {
				oldClient := cachedCoreOSClient.actualClient
				cachedCoreOSClient.ReplaceActualClient(newClient)
				oldClient.Close()
				log.Info("Successfully replaced Etcd Client with a new one for all future calls from this process...")
			}
		}
		log.Debug("Sleeping member update go-routine...")
		time.Sleep(time.Duration(30) * time.Second)
	}
}
