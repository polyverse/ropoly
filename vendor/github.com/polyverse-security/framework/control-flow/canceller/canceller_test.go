package canceller

/*

import (
	"time"
	"fmt"
	"os"
)


import (
	. "gopkg.in/check.v1"
	"testing"
	"time"
	"os"
	log "github.com/Sirupsen/logrus"
	"fmt"
)

func TestBackend(t *testing.T) { TestingT(t) }

type BackendSuite struct {
}

var _ = Suite(&BackendSuite{})

func (s *BackendSuite) TestCancellerCancels(c *C) {
	log.SetLevel(log.InfoLevel)
	canceller := NewCanceller(time.Duration(10) * time.Second)

	for i := 0; i < 100; i++ {
		go func() {
			cancelChan := make(chan bool, 1)
			canceller.AddCancelChannel(cancelChan)
			//defer canceller.Done()

			<- cancelChan
		}()
	}

	go func() {
		fmt.Printf("Goroutine for cancel signal started\n")
		time.Sleep(time.Duration(5) * time.Second)
		p, _ := os.FindProcess(os.Getpid())
		fmt.Printf("Cancel signal raised\n")
		p.Signal(os.Interrupt)
	}()

	fmt.Printf("Waiting for cancellation\n")
	canceller.WaitForCancellation()
}

*/
