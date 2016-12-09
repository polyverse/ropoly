package events

import (
	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/polyverse-security/framework/control-flow/canceller"
	"github.com/polyverse-security/framework/wiring"
	"golang.org/x/net/context"
)

type WatchEventHandler func(event *etcd.Event) error

type watchOptions struct {
	initEvents bool
}

func (w *watchOptions) apply(appliers []WatchOptionApplier) {
	for _, applier := range appliers {
		applier(w)
	}
}

type WatchOptionApplier func(*watchOptions)

func WithInitValues() WatchOptionApplier {
	return func(wo *watchOptions) {
		wo.initEvents = true
	}
}

func WatchEtcdKey(key string, action WatchEventHandler, appliers ...WatchOptionApplier) {
	WatchEtcdKeyWithCancel(nil, key, action, appliers...)
}

func WatchEtcdKeyWithCancel(canceller *canceller.Canceller, key string, action WatchEventHandler, appliers ...WatchOptionApplier) {
	wo := watchOptions{
		initEvents: true,
	}
	wo.apply(appliers)

	log.Debugf("Setting up listener for %v changes", key)
	etcdClient := wiring.NewEtcdClientCoreOS()
	log.Debug("Event listener acquired etcd client")

	cancelChan := make(chan bool, 1)
	if canceller != nil {
		canceller.AddCancelChannel(cancelChan)
		defer canceller.Done()
	}

	cancelCtx, cancelCtxFunc := context.WithCancel(context.Background())

	w := wiring.NewEtcdWatcher(etcdClient)
	if w == nil {
		log.Error("Watcher was nil. Continuing...")
		return
	}

	etcdOpOptions := []etcd.OpOption{etcd.WithPrefix()}

	if wo.initEvents {
		//get snapshot
		if resp, err := etcdClient.Get(context.Background(), key, etcd.WithPrefix()); err != nil {
			log.WithField("Error", err).Error("Error occurred when getting initial key states from etcd. Unable to begin watch.")
		} else {
			etcdOpOptions = append(etcdOpOptions, etcd.WithRev(resp.Header.Revision+1))
			for _, kv := range resp.Kvs {
				err := action(generatePutEvent(kv))
				if err != nil {
					log.WithField("Error", err).Errorf("Stopped listening for %v changes, because handler function returned an error.", key)
					return
				}
			}
		}
	}

	wc := w.Watch(cancelCtx, key, etcdOpOptions...)
	defer w.Close()
	for {
		select {
		case wr := <-wc:
			for _, event := range wr.Events {
				err := action(event)
				if err != nil {
					log.WithField("Error", err).Errorf("Stopped listening for %v changes, because handler function returned an error.", key)
					return
				}
			}
		case <-cancelChan:
			cancelCtxFunc() //Cancel any watch operations going on
			return
		}
	}
}

func generatePutEvent(kv *mvccpb.KeyValue) *etcd.Event {
	return &etcd.Event{
		Type: mvccpb.PUT,
		Kv:   kv,
	}
}
