package wiring

import (
	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/polyverse-security/framework/constants/components"
	"reflect"
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
	cachedCoreOSClient  EtcdClientCoreOS
	NewEtcdClientCoreOS etcdCoreOSFactory
	GetEtcdMachines     etcdMachinesFactory
	NewEtcdWatcher      etcdClientWatcherFactory
)

func init() {
	NewEtcdClientCoreOS = newEtcdClientCoreOS
	GetEtcdMachines = defaultEtcdMachines
	NewEtcdWatcher = newEtcdClientWatcher
}

func newEtcdClientCoreOS() EtcdClientCoreOS {
	if cachedCoreOSClient != nil {
		return cachedCoreOSClient
	}
	log.Info("Creating etcd client")

	cfg := etcd.Config{
		Endpoints:        GetEtcdMachines(),
		AutoSyncInterval: time.Duration(30) * time.Second,
	}
	if c, err := etcd.New(cfg); err != nil {
		log.WithFields(log.Fields{"Error": err, "Config": cfg}).Fatal("Unable to launch an etcd client based on the expected Etcd Endpoints.")
		return nil
	} else {
		log.WithFields(log.Fields{"etcdClient": c}).Debug("Etcd client factory created a client")
		cachedCoreOSClient = c
		return cachedCoreOSClient
	}
}

func newEtcdClientWatcher(client EtcdClientCoreOS) EtcdClientWatcher {
	if etcdClient, ok := client.(*etcd.Client); ok {
		return etcd.NewWatcher(etcdClient)
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
