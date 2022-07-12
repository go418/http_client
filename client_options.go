package http_client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/go418/http-client/dynamic_clientcert"
	"github.com/go418/http-client/dynamic_rootca"
	"github.com/go418/http-client/roundtrippers"
	"golang.org/x/net/http2"
)

func defaultClient() Option {
	return func(state *optionState) error {
		state.h1root = http.DefaultTransport.(*http.Transport).Clone()
		state.client = &http.Client{
			Transport: state.h1root,
		}
		return nil
	}
}

func dynamicClient() Option {
	return func(state *optionState) error {
		if h1root, ok := state.client.Transport.(*http.Transport); !ok {
			return fmt.Errorf("DynamicClient should be first registered RoundTripper")
		} else {
			state.dynamic = roundtrippers.NewDynamicTransportTripper(h1root)
			state.client.Transport = state.dynamic
			return nil
		}
	}
}

func Http2Transport(timeout time.Duration, keepAlive time.Duration) Option {
	return func(state *optionState) error {
		if h2root, err := http2.ConfigureTransports(state.h1root); err != nil {
			return err
		} else {
			state.h2root = h2root
			return nil
		}
	}
}

func DisableHttp2() Option {
	return func(state *optionState) error {
		if state.h2root != nil {
			return fmt.Errorf("HTTP2 has been enabled explicitly already")
		}
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		state.h1root.TLSClientConfig.NextProtos = []string{"http/1.1"}
		state.h1root.ForceAttemptHTTP2 = false
		return nil
	}
}

func DialContext(fn func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(state *optionState) error {
		state.h1root.DialContext = fn
		return nil
	}
}

func Proxy(proxy func(*http.Request) (*url.URL, error)) Option {
	return func(state *optionState) error {
		state.h1root.Proxy = proxy
		return nil
	}
}

func MaxIdleConnsPerHost(maxIdleConnsPerHost int) Option {
	return func(state *optionState) error {
		state.h1root.MaxConnsPerHost = maxIdleConnsPerHost
		return nil
	}
}

func Timeout(timeout time.Duration) Option {
	return func(state *optionState) error {
		state.client.Timeout = timeout
		return nil
	}
}

func defaultTlsConfig() *tls.Config {
	return &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion: tls.VersionTLS12,
	}
}

func TLSInsecureSkipVerify(insecureSkipVerify bool) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		state.h1root.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify
		return nil
	}
}

func TLSRootCAs(rootCAs *x509.CertPool) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		state.h1root.TLSClientConfig.RootCAs = rootCAs
		return nil
	}
}

func TLSClientCertificate(fn func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		if state.h1root.TLSClientConfig.GetClientCertificate != nil {
			return fmt.Errorf("GetClientCertificate has been set explicitly already")
		}
		state.h1root.TLSClientConfig.GetClientCertificate = fn
		return nil
	}
}

func filesCannotBeDifferent(file1 fs.FileInfo, file2 fs.FileInfo) bool {
	return os.SameFile(file1, file2) &&
		(file1.ModTime() == file2.ModTime()) &&
		(file1.Mode() == file2.Mode()) &&
		(file1.Size() == file2.Size())
}

type DynamicClientCertificateSource func(state *optionState) dynamic_clientcert.DynamicClientCertificate

func TLSDynamicClientCertificate(fn DynamicClientCertificateSource) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		if state.h1root.TLSClientConfig.GetClientCertificate != nil {
			return fmt.Errorf("GetClientCertificate has been set explicitly already")
		}
		state.h1root.TLSClientConfig.GetClientCertificate = fn(state).GetClientCertificate
		return nil
	}
}

func StartDynamicFileClientCertificateSource(ctx context.Context, log logr.Logger, certFile, keyFile string) (DynamicClientCertificateSource, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	var doneCh chan struct{}

	return DynamicClientCertificateSource(func(state *optionState) dynamic_clientcert.DynamicClientCertificate {
			var prevCertStat fs.FileInfo
			var prevKeyStat fs.FileInfo

			doneCh = make(chan struct{})

			dynamicClientCertificate := dynamic_clientcert.NewDynamicClientCertificate(
				ctx,
				log,
				func(ctx context.Context, existing *tls.Certificate) (*tls.Certificate, error) {
					certStat, err := os.Stat(certFile)
					if err != nil {
						return nil, fmt.Errorf("error checking client certificate file: %v", err)
					}

					keyStat, err := os.Stat(keyFile)
					if err != nil {
						return nil, fmt.Errorf("error checking client key file: %v", err)
					}

					if filesCannotBeDifferent(certStat, prevCertStat) && filesCannotBeDifferent(keyStat, prevKeyStat) {
						log.V(9).Info("detected no change in files", "certFile", certFile, "keyFile", keyFile)
						// Files have not changed, re-return existing certificate
						return existing, nil
					}
					log.V(8).Info("change detected in files", "certFile", certFile, "keyFile", keyFile)

					certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
					if err != nil {
						return nil, fmt.Errorf("could not load X509 key pair: %v", err)
					}

					// only update file stats here, since file-creation/ write could
					// be in progress, this will cause an error, resulting in a retry
					prevCertStat = certStat
					prevKeyStat = keyStat

					return &certificate, nil
				},
				state.h1root.DialContext,
			)

			go func() {
				defer close(doneCh)
				log.V(6).Info("starting certificate watch", "certFile", certFile, "keyFile", keyFile)
				defer log.V(6).Info("stopping certificate watch", "certFile", certFile, "keyFile", keyFile)
				dynamicClientCertificate.Run(ctx)
			}()

			return dynamicClientCertificate
		}), func() {
			cancel()
			if doneCh != nil {
				<-doneCh
			}
		}
}

func TLSTime(time func() time.Time) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}
		state.h1root.TLSClientConfig.Time = time
		return nil
	}
}

func TLSEnableSni() Option {
	return func(state *optionState) error {
		state.dynamic.RegisterTransportUpdater(func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error) {
			// check if TLS is enabled
			if transport.TLSClientConfig == nil {
				return transport, nil
			}

			host, _, err := net.SplitHostPort(req.URL.Host)
			if err != nil {
				return nil, err
			}

			// if ServerName is correct already, we can use the existing transport
			if transport.TLSClientConfig.ServerName == host {
				return transport, nil
			}

			// if transport is already a clone, skip creating a new clone
			if !isClone {
				transport = transport.Clone()
			}

			transport.TLSClientConfig.ServerName = host

			return transport, nil
		})
		return nil
	}
}

type DynamicRootCAsSource func(state *optionState) dynamic_rootca.DynamicRootCAs

func TLSDynamicRootCAs(fn DynamicRootCAsSource) Option {
	return func(state *optionState) error {
		if state.h1root.TLSClientConfig == nil {
			state.h1root.TLSClientConfig = defaultTlsConfig()
		}

		dynamicRootCAsSource := fn(state)

		state.dynamic.RegisterTransportUpdater(func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error) {
			if transport.TLSClientConfig == nil {
				return transport, nil
			}

			if certPool, err := dynamicRootCAsSource.GetCertPool(req.Context()); err != nil {
				return nil, err
			} else if transport.TLSClientConfig.RootCAs == certPool {
				return transport, nil
			} else {
				// if transport is already a clone, skip creating a new clone
				if !isClone {
					transport = transport.Clone()
				}

				transport.TLSClientConfig.RootCAs = certPool

				return transport, nil
			}
		})

		return nil
	}
}

// createErrorParsingCAData ALWAYS returns an error.  We call it because know we failed to AppendCertsFromPEM
// but we don't know the specific error because that API is just true/false
func createErrorParsingCAData(pemCerts []byte) error {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			return fmt.Errorf("unable to parse bytes as PEM block")
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	}
	return fmt.Errorf("no valid certificate authority data seen")
}

func StartDynamicFileRootCAsSource(ctx context.Context, log logr.Logger, rootCAFile string) (DynamicRootCAsSource, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	var doneCh chan struct{}

	return DynamicRootCAsSource(func(state *optionState) dynamic_rootca.DynamicRootCAs {
			var prevRootCAStat fs.FileInfo

			doneCh = make(chan struct{})

			dynamicClientCertificate := dynamic_rootca.NewDynamicClientCertificate(
				ctx,
				log,
				func(ctx context.Context, existing *x509.CertPool) (*x509.CertPool, error) {
					rootCAStat, err := os.Stat(rootCAFile)
					if err != nil {
						return nil, fmt.Errorf("error checking root CA file: %v", err)
					}

					if filesCannotBeDifferent(rootCAStat, prevRootCAStat) {
						log.V(9).Info("detected no change in files", "rootCAFile", rootCAFile)
						// Files have not changed, re-return existing certificate
						return existing, nil
					}
					log.V(8).Info("change detected in files", "rootCAFile", rootCAFile)

					certPool := x509.NewCertPool()

					der, err := ioutil.ReadFile(rootCAFile)
					if err != nil {
						return nil, err
					}
					if ok := certPool.AppendCertsFromPEM(der); !ok {
						return nil, createErrorParsingCAData(der)
					}

					// only update file stat here, since file-creation/ write could
					// be in progress, this will cause an error, resulting in a retry
					prevRootCAStat = rootCAStat

					return certPool, nil
				},
			)

			go func() {
				defer close(doneCh)
				log.V(6).Info("starting CA certificate watch", "rootCAFile", rootCAFile)
				defer log.V(6).Info("stopping CA certificate watch", "rootCAFile", rootCAFile)
				dynamicClientCertificate.Run(ctx)
			}()

			return dynamicClientCertificate
		}), func() {
			cancel()
			if doneCh != nil {
				<-doneCh
			}
		}
}

func Debug(log logr.Logger) Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewDebuggingRoundTripper(log, state.client.Transport)
		return nil
	}
}

func DisableCompression(disable bool) Option {
	return func(state *optionState) error {
		state.h1root.DisableCompression = disable
		if state.h2root != nil {
			state.h2root.DisableCompression = disable
		}
		return nil
	}
}

func AutoDeflate(enable bool) Option {
	disableCompression := DisableCompression(enable)
	return func(state *optionState) error {
		// Disable compression
		if err := disableCompression(state); err != nil {
			return err
		}

		// Add roundtripper that adds Gzip Accept-Encoding header,
		// since this is also disabled when disabling compression
		state.client.Transport = roundtrippers.NewGzipHeaderRoundTripper(state.client.Transport)
		return nil
	}
}

func AuthProxy(username string, groups []string, extra map[string][]string) Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewAuthProxyRoundTripper(username, groups, extra, state.client.Transport)
		return nil
	}
}

func BasicAuth(username, password string) Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewBasicAuthRoundTripper(username, password, state.client.Transport)
		return nil
	}
}

func BearerAuth(bearer string) Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewBearerAuthRoundTripper(bearer, state.client.Transport)
		return nil
	}
}

func BearerAuthWithRefresh(bearer string, tokenFile string) Option {
	return func(state *optionState) error {
		if transport, err := roundtrippers.NewBearerAuthWithRefreshRoundTripper(bearer, tokenFile, state.client.Transport); err != nil {
			return err
		} else {
			state.client.Transport = transport
			return nil
		}
	}
}

func UserAgent(userAgent string) Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewUserAgentRoundTripper(userAgent, state.client.Transport)
		return nil
	}
}

func cloneRequest() Option {
	return func(state *optionState) error {
		state.client.Transport = roundtrippers.NewRequestClonerRoundTripper(state.client.Transport)
		return nil
	}
}
