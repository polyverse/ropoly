package canceller

import (
	log "github.com/Sirupsen/logrus"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Canceller struct {
	mutex     sync.Mutex
	wg        *sync.WaitGroup
	channels  []chan bool
	timeout   time.Duration
	doneCount int64
}

func NewCanceller(timeout time.Duration) *Canceller {
	log.Debug("New Canceller requested.")
	return &Canceller{
		mutex:     sync.Mutex{},
		wg:        &sync.WaitGroup{},
		channels:  make([]chan bool, 0),
		timeout:   timeout,
		doneCount: 0,
	}
}

func (c *Canceller) AddCancelChannel(channel chan bool) {
	log.Debug("New Cancel Channel added to canceller. Storing it...")
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.wg.Add(1)
	c.channels = append(c.channels, channel)
	log.Debugf("Now tracking %d channels to send a cancel signal to.", len(c.channels))
}

func (c *Canceller) Done() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.doneCount++
	log.Debugf("Done called on canceller. %d of %d goroutines completed.", c.doneCount, len(c.channels))
	c.wg.Done()
}

func (c *Canceller) WaitForCancellation() {
	log.Debug("Wait for Cancellation requested. Registering signal listeners for SIGINT (CTRL+C) and SIGTERM (Sent by docker)")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM) //Docker sends Sigterm
	log.Debug("Registered signal listeners for SIGINT (CTRL+C) and SIGTERM (Sent by docker). Forking off a goroutine to call the cleanup.")
	go func() {
		sig := <-sigChan
		log.Infof("Cancel signal received: %v", sig)
		for _, channel := range c.channels {
			channel <- true
		}
		if c.timeout != 0 {
			log.Debugf("Cancellation signals sent out. Now waiting for timeout to expire: %v", c.timeout)
			time.Sleep(c.timeout)
			log.Panicf("Timeout %v expired before goroutines cleaned up after themselves. Some state may have been lost in this termination.", c.timeout)
		} else {
			log.Warningf("Timeout was set to zero. This means there IS no timeout here. Will wait until all goroutines clean up correctly. Waiting for %v goroutines.", len(c.channels))
		}
	}()

	log.Debug("Waiting for all goroutines to register Done() on the wait group. This is an infinite wait until the goroutines clean up.")
	c.wg.Wait()
	log.Debug("Wait group completed correctly. This means the app cleaned up correctly and successfully before shutting down.")
	os.Exit(0)
}
