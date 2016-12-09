package retry

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/reflection"
	"math/rand"
	"time"
)

const (
	StartBackoff = 500
	MaxBackoff   = 3 * 60 * 1000
)

func Retry(description string, op func() bool) {
	RetryLimited(description, func() error {
		res := op()
		if !res {
			return errors.New("failed")
		}
		return nil
	}, 0)
}

func RetryLimited(description string, op func() error, maxRetries int) error {
	attemptsFailed := 0
	backoff := StartBackoff
	for {
		var err error
		if err = op(); err == nil {
			log.Infof("%v successful", description)
			return nil
		}
		log.Warningf("Unable to %v. Cause: %v.", description, err)
		log.Debugf("Unable to %v. Cause: %v. Stack: %v", description, err, reflection.GetCallstackFormatted())
		attemptsFailed++
		if maxRetries > 0 && attemptsFailed > maxRetries {
			log.Errorf("Giving up to %v because of %v", description, err)
			return err
		}
		log.Infof("Retrying %v for %v th time", description, attemptsFailed)
		waitFor := time.Duration(backoff) * time.Millisecond
		time.Sleep(waitFor)
		jitter := rand.Intn(backoff/2+1) - backoff/2
		backoff = backoff*2 + jitter
		if backoff > MaxBackoff {
			backoff = MaxBackoff
		}
	}
}
