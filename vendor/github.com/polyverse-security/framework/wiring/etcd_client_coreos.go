package wiring

import (
	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/polyverse-security/framework/constants/components"
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
		Endpoints: GetEtcdMachines(),
	}
	if c, err := etcd.New(cfg); err != nil {
		log.WithFields(log.Fields{"Error": err, "Config": cfg}).Fatal("Unable to launch an etcd client based on the expected Etcd Endpoints.")
		return nil
	} else {
		etcdClient := c
		log.WithFields(log.Fields{"etcdClient": etcdClient}).Debug("Etcd client factory created a client")
		cachedCoreOSClient = etcdClient
		return cachedCoreOSClient
	}
}

func newEtcdClientWatcher(client EtcdClientCoreOS) EtcdClientWatcher {
	if etcdClient, ok := client.(*etcd.Client); ok {
		return etcd.NewWatcher(etcdClient)
	}
	return nil
}

func defaultEtcdMachines() []string {
	machines := []string{
		"polyverse_etcd_1:" + components.EtcdClientPort,
	}
	log.WithField("EtcdMachines", machines).Info("List of Etcd Machines Requested.")
	return machines
}
