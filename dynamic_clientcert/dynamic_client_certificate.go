package dynamic_clientcert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

// CertCallbackRefreshDuration is exposed so that integration tests can crank up the reload speed.
var CertCallbackRefreshDuration = 1 * time.Minute

type NewCertificate func(ctx context.Context, existing *tls.Certificate) (*tls.Certificate, error)

type decodedCertificate struct {
	Certificate *tls.Certificate
	RawIssuers  [][]byte    // list of all issuer identifiers of all certs in chain
	NotAfter    []time.Time // Validities of the certificates in the chain
}

type dynamicClientCert struct {
	log            logr.Logger
	NewCertificate NewCertificate

	certificate   atomic.Value
	certificateMu sync.Mutex
	connDialer    *dialer
}

type DynamicClientCertificate interface {
	// run starts the controller and blocks until context expires
	// calling run is not necessary, but allows us to refresh certificates
	// before being required for a request (preventing long latency penalties)
	Run(ctx context.Context)

	// GetClientCertificate can be used in you tls config. It makes sure a new
	// certificate is fetched when the current certificate is expired or does not
	// match the server's *tls.CertificateRequestInfo.
	GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// Dynamic client cert: use file/ secret watch and acceptable server CAs to determine
// if certificate is still valid and fetch a new version of the cerificate if required.
// A certificate that is about to expire will cause the connection to be closed.
func NewDynamicClientCertificate(ctx context.Context, log logr.Logger, newCertificate NewCertificate, dialContextFunc DialContextFunc) DynamicClientCertificate {
	return &dynamicClientCert{
		log:            log,
		NewCertificate: newCertificate,

		connDialer: NewDialer(dialContextFunc),
	}
}

// updateCertificate fetches a new certificate and rotates connections if needed
func (c *dynamicClientCert) renewCertificate(ctx context.Context, current *decodedCertificate) (*decodedCertificate, error) {
	shouldReset := false
	defer func() {
		// The first certificate requested is not a rotation that is worth closing connections for
		if shouldReset {
			c.connDialer.CloseAll()
		}
	}()

	c.certificateMu.Lock() // Lock to make sure we are not doing double work (only one renew at the time!)
	defer c.certificateMu.Unlock()

	decoded, _ := c.certificate.Load().(*decodedCertificate)
	if decoded != current {
		// since start of call the certificate has been updated, return
		return decoded, nil
	}
	if decoded == nil {
		decoded = &decodedCertificate{
			Certificate: nil,
		}
	}

	// the cool part about this approach is that NewCertificate has no concurrency problems
	// since it is locked behind the Mutex (so it can easily store state across calls)
	cert, err := c.NewCertificate(ctx, decoded.Certificate)
	if err != nil {
		return nil, err
	}

	if decoded.Certificate == cert || certsEqual(decoded.Certificate, cert) {
		// source noticed no change, so short circuit
		return decoded, nil
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("received invalid empty certificate")
	}

	if cert.Leaf == nil {
		if x509cert, err := x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		} else {
			cert.Leaf = x509cert
		}
	}

	decoded = &decodedCertificate{
		Certificate: cert,
		RawIssuers:  [][]byte{cert.Leaf.RawIssuer},
		NotAfter:    []time.Time{cert.Leaf.NotAfter},
	}

	for j := 1; j < len(cert.Certificate); j++ {
		if x509cert, err := x509.ParseCertificate(cert.Certificate[j]); err != nil {
			return nil, err
		} else {
			decoded.RawIssuers = append(decoded.RawIssuers, x509cert.RawIssuer)
			decoded.NotAfter = append(decoded.NotAfter, x509cert.NotAfter)
		}
	}

	c.certificate.Store(decoded)

	// reset all connections that are open (on first run, no connections should be open)
	shouldReset = true

	return decoded, nil
}

// run starts the controller and blocks until context expires
// all this logic is not necessary, but allows us to refresh certificates
// before being required for a request (preventing long latency penalties)
func (c *dynamicClientCert) Run(ctx context.Context) {
	renewMoment := time.Now()

	timer := time.NewTimer(time.Until(renewMoment))
	defer timer.Stop()

	decoded, _ := c.certificate.Load().(*decodedCertificate)

	for {
		renewMoment = time.Now().Add(CertCallbackRefreshDuration)

		newDecoded, err := c.renewCertificate(ctx, decoded)
		if err != nil {
			c.log.V(0).Error(err, "could not renew certificate")
		}
		// we got a new certificate,
		if newDecoded != nil && err == nil {
			notAfter, notBefore := newDecoded.Certificate.Leaf.NotAfter, newDecoded.Certificate.Leaf.NotBefore
			newRenewMoment := notAfter.Add(notAfter.Sub(notBefore) / -3)

			// only use certificate expiration if it means we can wait for a longer time
			// or we just received a new certificate, different from our previous certificate
			if newRenewMoment.After(renewMoment) || newDecoded != decoded {
				renewMoment = newRenewMoment
			}

			decoded = newDecoded
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

// certsEqual compares tls Certificates, ignoring the Leaf which may get filled in dynamically
func certsEqual(left, right *tls.Certificate) bool {
	if left == right {
		return true
	}

	if left == nil || right == nil {
		return left == right
	}

	if !byteMatrixEqual(left.Certificate, right.Certificate) {
		return false
	}

	if !reflect.DeepEqual(left.PrivateKey, right.PrivateKey) {
		return false
	}

	if !byteMatrixEqual(left.SignedCertificateTimestamps, right.SignedCertificateTimestamps) {
		return false
	}

	if !bytes.Equal(left.OCSPStaple, right.OCSPStaple) {
		return false
	}

	return true
}

func byteMatrixEqual(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}

// optimized version of cri.SupportsCertificate()
func (c *dynamicClientCert) supportsCertificate(cri *tls.CertificateRequestInfo, cert *decodedCertificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// remove AcceptableCAs from cri to short circuit cri.SupportsCertificate
	// the AcceptableCAs are checked seperately in this function
	var acceptableCAs [][]byte
	acceptableCAs, cri.AcceptableCAs = cri.AcceptableCAs, nil
	if err := cri.SupportsCertificate(cert.Certificate); err != nil {
		return err
	}
	cri.AcceptableCAs = acceptableCAs

	currentTime := time.Now()
	// for each certificate in chain, check if certificate is still valid
	// and if it is directly trusted by the server, if not look at next cert
	// in the chain.
	for i, rawIssuer := range cert.RawIssuers {
		if currentTime.After(cert.NotAfter[i]) {
			return fmt.Errorf("chain is no longer valid")
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(rawIssuer, ca) {
				return nil
			}
		}
	}

	return fmt.Errorf("chain is not signed by an acceptable CA")
}

func (c *dynamicClientCert) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	decoded, _ := c.certificate.Load().(*decodedCertificate)

	if err := c.supportsCertificate(cri, decoded); err != nil {
		c.log.V(8).Info("existing certificate is not valid anymore, try renewing", "error", err)

		// try reloading the certificate
		if decoded, err = c.renewCertificate(cri.Context(), decoded); err != nil {
			return nil, err
		}

		// check if the new certificate is accepted by the server
		if err := c.supportsCertificate(cri, decoded); err != nil {
			return nil, err
		}
	}

	return decoded.Certificate, nil
}
