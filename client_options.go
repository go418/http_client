package http_client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/go418/http_client/dynamic_clientcert"
	"github.com/go418/http_client/dynamic_rootca"
	"github.com/go418/http_client/roundtrippers"
)

var defaultTransport = createDefaultTransport()

func createDefaultTlsConfig() *tls.Config {
	return &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion: tls.VersionTLS12,
	}
}

func createDefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       createDefaultTlsConfig(),
	}
}

// Copys all the fields of the provided client,
// except for the Transport, which is skipped.
func ManualClient(client *http.Client) Option {
	return func(state *OptionState) error {
		if client == nil {
			client = &http.Client{}
		}

		transport := state.Client.Transport // save current transport
		*state.Client = *client             // copy all client's fields
		state.Client.Transport = transport  // restore transport

		return nil
	}
}

func DefaultClient() Option {
	return ManualClient(nil)
}

func ManualTransport(transport *http.Transport) Option {
	return func(state *OptionState) error {
		if transport == nil {
			transport = defaultTransport
		}

		state.Dynamic.RegisterTransportCreator(func(_ *http.Transport, _ bool) (*http.Transport, bool, error) {
			return transport, false, nil
		})

		return nil
	}
}

func DefaultTransport() Option {
	return ManualTransport(nil)
}

func EnableOption(enable bool, option Option) Option {
	if !enable {
		return func(state *OptionState) error { return nil }
	}
	return option
}

func EnableHttp2(enabled bool) Option {
	return func(state *OptionState) error {
		if enabled {
			state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		}
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if !isClone {
				transport = transport.Clone()
			}
			if enabled {
				transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
				transport.ForceAttemptHTTP2 = true
			} else {
				transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
				transport.ForceAttemptHTTP2 = false
			}

			return transport, true, nil
		})
		return nil
	}
}

func DialContext(fn func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if !isClone {
				transport = transport.Clone()
			}
			transport.DialContext = fn

			return transport, true, nil
		})
		return nil
	}
}

func Proxy(proxy func(*http.Request) (*url.URL, error)) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if !isClone {
				transport = transport.Clone()
			}
			transport.Proxy = proxy

			return transport, true, nil
		})
		return nil
	}
}

func MaxIdleConnsPerHost(maxIdleConnsPerHost int) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.MaxConnsPerHost == maxIdleConnsPerHost {
				return transport, isClone, nil
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.MaxConnsPerHost = maxIdleConnsPerHost

			return transport, true, nil
		})
		return nil
	}
}

func Timeout(timeout time.Duration) Option {
	return func(state *OptionState) error {
		state.Client.Timeout = timeout
		return nil
	}
}

func defaultTlsConfig(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
	if transport.TLSClientConfig != nil {
		return transport, isClone, nil
	}

	if !isClone {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = createDefaultTlsConfig()

	return transport, true, nil
}

func TLSRenegotation(renegotiationSupport tls.RenegotiationSupport) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.TLSClientConfig.Renegotiation == renegotiationSupport {
				return transport, isClone, nil
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.TLSClientConfig.Renegotiation = renegotiationSupport

			return transport, true, nil
		})
		return nil
	}
}

func TLSInsecureSkipVerify(insecureSkipVerify bool) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.TLSClientConfig.InsecureSkipVerify == insecureSkipVerify {
				return transport, isClone, nil
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify

			return transport, true, nil
		})
		return nil
	}
}

func TLSRootCAs(rootCAs *x509.CertPool) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.TLSClientConfig.RootCAs == rootCAs {
				return transport, isClone, nil
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.TLSClientConfig.RootCAs = rootCAs

			return transport, true, nil
		})
		return nil
	}
}

func TLSClientCertificate(fn func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.TLSClientConfig.GetClientCertificate != nil {
				return nil, false, fmt.Errorf("GetClientCertificate has been set explicitly already")
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.TLSClientConfig.GetClientCertificate = fn

			return transport, true, nil
		})
		return nil
	}
}

type DynamicClientCertificateSource func(state *OptionState) dynamic_clientcert.DynamicClientCertificate

func TLSDynamicClientCertificate(fn DynamicClientCertificateSource) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.TLSClientConfig.GetClientCertificate != nil {
				return nil, false, fmt.Errorf("GetClientCertificate has been set explicitly already")
			}

			if !isClone {
				transport = transport.Clone()
			}

			dynamicClientCertificateSource := fn(state)
			transport.TLSClientConfig.GetClientCertificate = dynamicClientCertificateSource.GetClientCertificate

			return transport, true, nil
		})
		return nil
	}
}

func StartDynamicFileClientCertificateSource(ctx context.Context, log logr.Logger, certFile, keyFile string) (DynamicClientCertificateSource, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	var doneCh chan struct{}

	return DynamicClientCertificateSource(func(state *OptionState) dynamic_clientcert.DynamicClientCertificate {
			doneCh = make(chan struct{})

			dynamicClientCertificate := dynamic_clientcert.NewDynamicClientCertificate(
				ctx,
				log,
				func(ctx context.Context, existing *tls.Certificate) (*tls.Certificate, error) {
					log.V(8).Info("reloading client certificate", "certFile", certFile, "keyFile", keyFile)

					certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
					if err != nil {
						return nil, fmt.Errorf("could not load X509 key pair: %v", err)
					}

					return &certificate, nil
				},
				state.Dynamic.CloseIdleConnections,
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
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if !isClone {
				transport = transport.Clone()
			}
			transport.TLSClientConfig.Time = time

			return transport, true, nil
		})
		return nil
	}
}

func TLSEnableSni() Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportUpdater(func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error) {
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

type DynamicRootCAsSource func(state *OptionState) dynamic_rootca.DynamicRootCAs

func TLSDynamicRootCAs(fn DynamicRootCAsSource) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(defaultTlsConfig)

		dynamicRootCAsSource := fn(state)
		state.Dynamic.RegisterTransportUpdater(func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error) {
			if transport.TLSClientConfig == nil { // TLS disabled
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

	return DynamicRootCAsSource(func(state *OptionState) dynamic_rootca.DynamicRootCAs {
			doneCh = make(chan struct{})

			dynamicClientCertificate := dynamic_rootca.NewDynamicClientCertificate(
				ctx,
				log,
				func(ctx context.Context, existing *x509.CertPool) (*x509.CertPool, error) {
					log.V(8).Info("reloading root CA file", "rootCAFile", rootCAFile)

					certPool := x509.NewCertPool()

					der, err := ioutil.ReadFile(rootCAFile)
					if err != nil {
						return nil, err
					}
					if ok := certPool.AppendCertsFromPEM(der); !ok {
						return nil, createErrorParsingCAData(der)
					}

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
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewDebuggingRoundTripper(log, state.Client.Transport)
		return nil
	}
}

func DisableCompression(disable bool) Option {
	return func(state *OptionState) error {
		state.Dynamic.RegisterTransportCreator(func(transport *http.Transport, isClone bool) (*http.Transport, bool, error) {
			if transport.DisableCompression == disable {
				return transport, isClone, nil
			}

			if !isClone {
				transport = transport.Clone()
			}
			transport.DisableCompression = disable

			return transport, true, nil
		})
		return nil
	}
}

func AutoDeflate(enable bool) Option {
	disableCompression := DisableCompression(enable)
	return func(state *OptionState) error {
		// Disable compression
		if err := disableCompression(state); err != nil {
			return err
		}

		// Add roundtripper that adds Gzip Accept-Encoding header,
		// since this is also disabled when disabling compression
		state.Client.Transport = roundtrippers.NewGzipHeaderRoundTripper(state.Client.Transport)
		return nil
	}
}

func AuthProxy(username string, groups []string, extra map[string][]string) Option {
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewAuthProxyRoundTripper(username, groups, extra, state.Client.Transport)
		return nil
	}
}

func BasicAuth(username, password string) Option {
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewBasicAuthRoundTripper(username, password, state.Client.Transport)
		return nil
	}
}

func BearerAuth(bearer string) Option {
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewBearerAuthRoundTripper(bearer, state.Client.Transport)
		return nil
	}
}

func BearerAuthWithRefresh(bearer string, tokenFile string) Option {
	return func(state *OptionState) error {
		if transport, err := roundtrippers.NewBearerAuthWithRefreshRoundTripper(bearer, tokenFile, state.Client.Transport); err != nil {
			return err
		} else {
			state.Client.Transport = transport
			return nil
		}
	}
}

func UserAgent(userAgent string) Option {
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewUserAgentRoundTripper(userAgent, state.Client.Transport)
		return nil
	}
}

func ManualCloneRequest() Option {
	return func(state *OptionState) error {
		state.Client.Transport = roundtrippers.NewRequestClonerRoundTripper(state.Client.Transport)
		return nil
	}
}

func RoundTripper(fn func(http.RoundTripper) (http.RoundTripper, error)) Option {
	return func(state *OptionState) error {
		if transport, err := fn(state.Client.Transport); err != nil {
			return err
		} else {
			state.Client.Transport = transport
			return nil
		}
	}
}
