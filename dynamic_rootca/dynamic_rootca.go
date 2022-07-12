package dynamic_rootca

import (
	"context"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

// CertCallbackRefreshDuration is exposed so that integration tests can crank up the reload speed.
var CertCallbackRefreshDuration = 5 * time.Minute

type NewCertPool func(ctx context.Context, existing *x509.CertPool) (*x509.CertPool, error)

type dynamicRootCAs struct {
	log         logr.Logger
	NewCertPool NewCertPool

	certPool   atomic.Value
	certPoolMu sync.Mutex
}

type DynamicRootCAs interface {
	// run starts the controller and blocks until context expires
	// calling run is not necessary, but allows us to refresh certificates
	// before being required for a request (preventing long latency penalties)
	Run(ctx context.Context)

	// GetCertPool returns the latest CA bundle that was read. The controller
	// tries to reload the certificates periodically.
	GetCertPool(ctx context.Context) (*x509.CertPool, error)
}

// Dynamic client cert: use file/ secret watch and acceptable server CAs to determine
// if certificate is still valid and fetch a new version of the cerificate if required.
// A certificate that is about to expire will cause the connection to be closed.
func NewDynamicClientCertificate(ctx context.Context, log logr.Logger, newCertPool NewCertPool) DynamicRootCAs {
	return &dynamicRootCAs{
		log:         log,
		NewCertPool: newCertPool,
	}
}

// updateCertificate fetches a new certificate and rotates connections if needed
func (c *dynamicRootCAs) renewCertificate(ctx context.Context, current *x509.CertPool) (*x509.CertPool, error) {
	c.certPoolMu.Lock() // Lock to make sure we are not doing double work (only one renew at the time!)
	defer c.certPoolMu.Unlock()

	certPool, _ := c.certPool.Load().(*x509.CertPool)
	if certPool != current {
		// since start of call the certificate has been updated, return
		return certPool, nil
	}

	// the cool part about this approach is that NewCertPool has no concurrency problems
	// since it is locked behind the Mutex (so it can easily store state across calls)
	newCertPool, err := c.NewCertPool(ctx, certPool)
	if err != nil {
		return nil, err
	}

	if newCertPool == certPool {
		// source noticed no change, so short circuit
		return certPool, nil
	}

	c.certPool.Store(newCertPool)

	return newCertPool, nil
}

// run starts the controller and blocks until context expires
// all this logic is not necessary, but allows us to refresh certificates
// before being required for a request (preventing long latency penalties)
func (c *dynamicRootCAs) Run(ctx context.Context) {
	renewMoment := time.Now()

	timer := time.NewTimer(time.Until(renewMoment))
	defer timer.Stop()

	for {
		renewMoment = time.Now().Add(CertCallbackRefreshDuration)

		certPool, _ := c.certPool.Load().(*x509.CertPool)
		_, err := c.renewCertificate(ctx, certPool)
		if err != nil {
			c.log.V(0).Error(err, "could not renew CertPool")
		}

		// stop timer, drain and reset
		timer.Stop()
	Drain:
		for {
			select {
			case <-timer.C:
			default:
				break Drain
			}
		}
		waitFor := time.Until(renewMoment)
		c.log.V(8).Info("scheduled renewal", "delay", waitFor)
		timer.Reset(waitFor)

		// wait for timer
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.log.V(9).Info("start renew")
		}
	}
}

func (c *dynamicRootCAs) GetCertPool(ctx context.Context) (*x509.CertPool, error) {
	certPool, _ := c.certPool.Load().(*x509.CertPool)

	if certPool == nil {
		c.log.V(8).Info("no certificate has been found yet, try renewing")

		// try reloading the certificate
		var err error
		if certPool, err = c.renewCertificate(ctx, certPool); err != nil {
			return nil, err
		}

		return certPool, nil
	}

	return certPool, nil
}
