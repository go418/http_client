package http_client_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	resolver "github.com/aojea/mem-resolver"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/go418/http_client"
	"github.com/go418/http_client/dynamic_clientcert"
	"github.com/go418/http_client/dynamic_rootca"
	"github.com/tonglil/buflogr"
)

func boolPtr(b bool) *bool {
	return &b
}

func generateCaCertificate(
	t *testing.T,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	client *bool,
	hosts []string,
	notBefore time.Time,
	notAfter time.Time,
) (*ecdsa.PrivateKey, []byte, *x509.Certificate) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	if notAfter.IsZero() {
		notAfter = notBefore.Add(1 * time.Hour)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Cert 123 Inc."},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
	}

	if parentCert == nil {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.IsCA = true
		template.MaxPathLen = 0
		template.MaxPathLenZero = true
		template.Subject.CommonName = "CA"
		parentCert = &template
		parentKey = priv
	}

	if client != nil {
		if *client {
			template.KeyUsage |= x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.Subject.CommonName = "Client TLS"
		} else {
			template.KeyUsage |= x509.KeyUsageDigitalSignature
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.Subject.CommonName = "Server TLS"
		}
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return priv, derBytes, cert
}

func infoWriter() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			w.WriteHeader(500)
		}

		if _, err := w.Write(dump); err != nil {
			w.WriteHeader(500)
		}
	})
}

func testTlsServerEnv(t *testing.T, enableHttp2 bool, serverCerts []tls.Certificate, clientCAs *x509.CertPool) (*url.URL, func()) {
	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  enableHttp2,
		ClientCAs:    clientCAs,
		Certificates: serverCerts,
	}
	cancel := testServer.Start()
	return testServer.URL, cancel
}

func checkResponse(t *testing.T, client *http.Client, req *http.Request, expectedRequest *http.Request, checkError func(error) bool) {
	t.Helper()

	res, err := client.Do(req)
	if (err == nil) && (checkError == nil) {
	} else if (err != nil) && (checkError != nil) && checkError(err) {
		return
	} else if checkError != nil {
		t.Fatalf("expected error, got wrong error %v instead", err)
	} else if err != nil {
		t.Fatalf("could not perform request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		if expectedRequest == nil {
			return
		}

		t.Fatalf("unexpected status code: %d", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("could not read response body: %v", err)
	}

	dump, err := httputil.DumpRequest(expectedRequest, true)
	if err != nil {
		t.Fatalf("could not encode expected request: %v", err)
	}

	if string(data) != string(dump) {
		t.Fatalf("requests don't match, expected '%s', got '%s'", string(dump), string(data))
	}
}

func TestDoRequestSuccess(t *testing.T) {
	generatedBody := "dummy data"
	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	c, err := http_client.NewClient(
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL:  testUrl,
			Body: io.NopCloser(bytes.NewBufferString(generatedBody)),
		},
		&http.Request{
			URL:              testUrl,
			ProtoMajor:       1,
			ProtoMinor:       1,
			TransferEncoding: []string{"chunked"},
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
			Body: io.NopCloser(bytes.NewBufferString(generatedBody)),
		}, nil)
}

func TestHTTPProxy(t *testing.T) {
	generatedBody := "dummy data"
	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	testProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		to, err := url.Parse(req.RequestURI)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		httputil.NewSingleHostReverseProxy(to).ServeHTTP(w, req)
	}))
	defer testProxyServer.Close()

	u, err := url.Parse(testProxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse test proxy server url: %v", err)
	}

	c, err := http_client.NewClient(
		http_client.Proxy(http.ProxyURL(u)),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	checkResponse(t, c,
		&http.Request{
			URL:  testUrl,
			Body: io.NopCloser(bytes.NewBufferString(generatedBody)),
		},
		&http.Request{
			URL:              testUrl,
			ProtoMajor:       1,
			ProtoMinor:       1,
			TransferEncoding: []string{"chunked"},
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
				"X-Forwarded-For": []string{"127.0.0.1"},
			},
			Body: io.NopCloser(bytes.NewBufferString(generatedBody)),
		}, nil)
}

func TestClientAuth(t *testing.T) {
	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	c, err := http_client.NewClient(
		http_client.BasicAuth("user", "pass"),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"Authorization":   []string{"Basic dXNlcjpwYXNz"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestBearerAuth(t *testing.T) {
	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	c, err := http_client.NewClient(
		http_client.BearerAuth("aaaaaaaaaaa"),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"Authorization":   []string{"Bearer aaaaaaaaaaa"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestInsecureTLSHttp2(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSInsecureSkipVerify(true),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestHttp2Fail(t *testing.T) {
	testUrl, cancel := testTlsServerEnv(t, true, nil, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil, func(err error) bool {
			return strings.Contains(err.Error(), "tls: unrecognized name")
		})
}

func TestRootCAHttp2(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestRootCAHttp1(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, false, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestCAmTLS(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, clientCertPool)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil

		}),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestPKImTLS(t *testing.T) {
	serverCAPriv, _, serverCACert := generateCaCertificate(t, nil, nil, nil, []string{}, time.Time{}, time.Time{})
	serverPriv, serverCertBytes, _ := generateCaCertificate(t, serverCACert, serverCAPriv, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCACert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientCAPriv, _, clientCACert := generateCaCertificate(t, nil, nil, nil, []string{}, time.Time{}, time.Time{})
	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, clientCACert, clientCAPriv, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCACert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, clientCertPool)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			var acceptedCA []byte
			for _, acceptedCA = range cri.AcceptableCAs {
				if string(acceptedCA) != string(clientCert.RawIssuer) {
					continue
				}
				return clientTlsCert, nil
			}

			return nil, fmt.Errorf("cert is not accepted, expected '%s', got '%s'", string(clientCert.RawIssuer), string(cri.AcceptableCAs[0]))
		}),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestPKImTLSCustomNames(t *testing.T) {
	serverURL := "server.cloudweb123"
	clientURL := "client.cloudweb123"

	serverCAPriv, _, serverCACert := generateCaCertificate(t, nil, nil, nil, []string{}, time.Time{}, time.Time{})
	serverPriv, serverCertBytes, _ := generateCaCertificate(t, serverCACert, serverCAPriv, boolPtr(false), []string{serverURL}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCACert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientCAPriv, _, clientCACert := generateCaCertificate(t, nil, nil, nil, []string{}, time.Time{}, time.Time{})
	clientPriv, clientCertBytes, _ := generateCaCertificate(t, clientCACert, clientCAPriv, boolPtr(true), []string{clientURL}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCACert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: resolver.NewMemoryResolver(&resolver.MemResolver{
			LookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
				// fqdn appends a dot
				if serverURL == strings.TrimSuffix(host, ".") {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
				return net.DefaultResolver.LookupIP(ctx, network, host)
			},
		}),
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, clientCertPool)
	defer cancel()

	testUrl.Host = strings.Replace(testUrl.Host, "127.0.0.1", serverURL, 1)

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
		http_client.DialContext(dialer.DialContext),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestHttp1OnHttp2Server(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.EnableHttp2(false),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestHttp2OnHttp1Server(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, false, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestCAmTLSWithSNI(t *testing.T) {
	server1URL := "server1.cloudweb123"
	server1Priv, server1CertBytes, server1Cert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{server1URL}, time.Time{}, time.Time{})
	server1CertPool := x509.NewCertPool()
	server1CertPool.AddCert(server1Cert)
	server1TlsCert := &tls.Certificate{
		Certificate: [][]byte{server1CertBytes},
		PrivateKey:  server1Priv,
	}

	server2URL := "server2.cloudweb123"
	server2Priv, server2CertBytes, server2Cert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{server2URL}, time.Time{}, time.Time{})
	server2CertPool := x509.NewCertPool()
	server2CertPool.AddCert(server2Cert)
	server2TlsCert := &tls.Certificate{
		Certificate: [][]byte{server2CertBytes},
		PrivateKey:  server2Priv,
	}

	returnCert := func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if helloInfo.ServerName == server1URL {
			return server1TlsCert, nil
		} else if helloInfo.ServerName == server2URL {
			return server2TlsCert, nil
		}
		return nil, fmt.Errorf("server name '%s' is unknown", helloInfo.ServerName)
	}

	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: resolver.NewMemoryResolver(&resolver.MemResolver{
			LookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
				// fqdn appends a dot
				if server1URL == strings.TrimSuffix(host, ".") {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
				if server2URL == strings.TrimSuffix(host, ".") {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
				return net.DefaultResolver.LookupIP(ctx, network, host)
			},
		}),
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testServer := &http_client.Server{
		Config:         &http.Server{Handler: infoWriter()},
		TLS:            true,
		EnableHTTP2:    true,
		ClientCAs:      clientCertPool,
		GetCertificate: returnCert,
	}
	defer testServer.Start()()
	testUrl := testServer.URL
	testUrl.Host = strings.Replace(testUrl.Host, "127.0.0.1", server2URL, 1)

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(server2CertPool),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
		http_client.DialContext(dialer.DialContext),
		http_client.TLSEnableSni(),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestDebug(t *testing.T) {
	serverURL := "server.cloudweb123"

	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL
	testUrl.Host = strings.Replace(testUrl.Host, "127.0.0.1", serverURL, 1)

	var buf bytes.Buffer
	var log logr.Logger = buflogr.NewWithBuffer(&buf)

	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: resolver.NewMemoryResolver(&resolver.MemResolver{
			LookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
				// fqdn appends a dot
				if serverURL == strings.TrimSuffix(host, ".") {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
				return net.DefaultResolver.LookupIP(ctx, network, host)
			},
		}),
	}

	c, err := http_client.NewClient(
		http_client.BasicAuth("user", "pass"),
		http_client.UserAgent("test"),
		http_client.DialContext(dialer.DialContext),
		http_client.Debug(log),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			Method: http.MethodGet,
			URL:    testUrl,
		},
		&http.Request{
			Method:     http.MethodGet,
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"Authorization":   []string{"Basic dXNlcjpwYXNz"},
				"User-Agent":      []string{"test"},
			},
		}, nil)

	expectedLog := `V\[6\] HTTP request start requestId 1 verb url http:\/\/server\.cloudweb123:\d+
V\[7\] HTTP request headers requestId 1 ((Authorization Basic <masked>\s*)|(User-Agent test\s*))+
V\[8\] HTTP trace: DNS lookup requestId 1 host server.cloudweb123 resolved \[{127.0.0.1 }\]
V\[8\] HTTP trace: dial requestId 1 network tcp key (.*) status success
V\[7\] HTTP statistics requestId 1 DNS lookup \(ms\) \d+ dial \(ms\) \d+ TLS handshake \(ms\) \d+ ServerProcessing \(ms\) \d+ duration \(ms\) \d+
V\[7\] HTTP response headers requestId 1 (.*)`

	if ok, err := regexp.Match(expectedLog, buf.Bytes()); !ok || err != nil {
		t.Errorf("expected to log '%s', got '%s' instead", expectedLog, buf.String())
	}
}

func TestDebugBody(t *testing.T) {
	serverURL := "server.cloudweb123"

	testServer := &http_client.Server{
		Config: &http.Server{Handler: infoWriter()},
		TLS:    false,
	}
	defer testServer.Start()()
	testUrl := testServer.URL
	testUrl.Host = strings.Replace(testUrl.Host, "127.0.0.1", serverURL, 1)

	var buf bytes.Buffer
	var log logr.Logger = buflogr.NewWithBuffer(&buf)

	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: resolver.NewMemoryResolver(&resolver.MemResolver{
			LookupIP: func(ctx context.Context, network, host string) ([]net.IP, error) {
				// fqdn appends a dot
				if serverURL == strings.TrimSuffix(host, ".") {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
				return net.DefaultResolver.LookupIP(ctx, network, host)
			},
		}),
	}

	c, err := http_client.NewClient(
		http_client.BasicAuth("user", "pass"),
		http_client.UserAgent("test"),
		http_client.DialContext(dialer.DialContext),
		http_client.Debug(log),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			Method: http.MethodPost,
			URL:    testUrl,
			Body:   ioutil.NopCloser(bytes.NewBufferString("test")),
		},
		&http.Request{
			Method:           http.MethodPost,
			URL:              testUrl,
			ProtoMajor:       1,
			ProtoMinor:       1,
			TransferEncoding: []string{"chunked"},
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"Authorization":   []string{"Basic dXNlcjpwYXNz"},
				"User-Agent":      []string{"test"},
			},
			Body: ioutil.NopCloser(bytes.NewBufferString("test")),
		}, nil)

	expectedLog := `V\[6\] HTTP request start requestId 1 verb url http:\/\/server\.cloudweb123:\d+
V\[7\] HTTP request headers requestId 1 ((Authorization Basic <masked>\s*)|(User-Agent test\s*))+
V\[8\] HTTP trace: DNS lookup requestId 1 host server.cloudweb123 resolved \[{127.0.0.1 }\]
V\[8\] HTTP trace: dial requestId 1 network tcp key (.*) status success
V\[9\] HTTP request body requestId 1 body test
V\[7\] HTTP statistics requestId 1 DNS lookup \(ms\) \d+ dial \(ms\) \d+ TLS handshake \(ms\) \d+ ServerProcessing \(ms\) \d+ duration \(ms\) \d+
V\[7\] HTTP response headers requestId 1 (.*)`

	if ok, err := regexp.Match(expectedLog, buf.Bytes()); !ok || err != nil {
		t.Errorf("expected to log '%s', got '%s' instead", expectedLog, buf.String())
	}
}

func TestNotYetValidServerCertificate(t *testing.T) {
	serverNotBefore := time.Now()
	serverNotAfter := serverNotBefore.Add(5 * time.Hour)
	clientTime := serverNotBefore.Add(-1 * time.Second)

	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, serverNotBefore, serverNotAfter)
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, false, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSTime(func() time.Time {
			return clientTime
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil,
		func(err error) bool {
			return strings.Contains(err.Error(), "x509: certificate has expired or is not yet valid: current time") &&
				strings.Contains(err.Error(), "is before")
		})
}

func TestExpiredServerCertificate(t *testing.T) {
	serverNotBefore := time.Now()
	serverNotAfter := serverNotBefore.Add(5 * time.Hour)
	clientTime := serverNotAfter.Add(1 * time.Second)

	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, serverNotBefore, serverNotAfter)
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, false, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSTime(func() time.Time {
			return clientTime
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil,
		func(err error) bool {
			return strings.Contains(err.Error(), "x509: certificate has expired or is not yet valid: current time") &&
				strings.Contains(err.Error(), "is after")
		})
}

func TestNotYetValidClientCertificate(t *testing.T) {
	clientNotBefore := time.Now()
	clientNotAfter := clientNotBefore.Add(5 * time.Hour)
	serverTime := clientNotBefore.Add(-1 * time.Second)

	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, clientNotBefore, clientNotAfter)
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
		Time:         func() time.Time { return serverTime },
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil,
		func(err error) bool {
			return strings.Contains(err.Error(), "remote error: tls: bad certificate")
		})
}

func TestExpiredClientCertificate(t *testing.T) {
	clientNotBefore := time.Now()
	clientNotAfter := clientNotBefore.Add(5 * time.Hour)
	serverTime := clientNotAfter.Add(1 * time.Second)

	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, clientNotBefore, clientNotAfter)
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
		Time:         func() time.Time { return serverTime },
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil,
		func(err error) bool {
			return strings.Contains(err.Error(), "remote error: tls: bad certificate")
		})
}

func saveCertificate(t *testing.T, tempDir string, derBytes []byte, priv *ecdsa.PrivateKey) (string, string) {
	certFilePath := path.Join(tempDir, "cert.pem")
	keyFilePath := path.Join(tempDir, "key.pem")

	certOut, err := os.Create(certFilePath)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			t.Fatalf("Error closing cert.pem: %v", err)
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	t.Logf("wrote %s", certFilePath)

	keyOut, err := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	defer func() {
		if err := keyOut.Close(); err != nil {
			t.Fatalf("Error closing key.pem: %v", err)
		}
	}()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to write data to key.pem: %v", err)
	}
	t.Logf("wrote %s", keyFilePath)

	return certFilePath, keyFilePath
}

func TestDynamicClientCertificate(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientCertPath, clientKeyPath := saveCertificate(t, t.TempDir(), clientCertBytes, clientPriv)

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	dynamicClientCertSource, cancel := http_client.StartDynamicFileClientCertificateSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), clientCertPath, clientKeyPath)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSDynamicClientCertificate(dynamicClientCertSource),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestDynamicClientCertificateLate(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	tempDir := t.TempDir()
	clientCertPath, clientKeyPath := saveCertificate(t, tempDir, clientCertBytes, clientPriv)
	os.Remove(clientCertPath) // delete file, and recreate later
	os.Remove(clientKeyPath)  // delete file, and recreate later

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	dynamicClientCertSource, cancel := http_client.StartDynamicFileClientCertificateSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), clientCertPath, clientKeyPath)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSDynamicClientCertificate(dynamicClientCertSource),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil, func(err error) bool {
			return strings.Contains(err.Error(), "no such file or directory")
		})

	_, _ = saveCertificate(t, tempDir, clientCertBytes, clientPriv)

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestDynamicClientCertificateRenew(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}
	tempDir := t.TempDir()
	clientCertPath, clientKeyPath := path.Join(tempDir, "cert.pem"), path.Join(tempDir, "key.pem")

	dynamic_clientcert.CertCallbackRefreshDuration = 100 * time.Millisecond

	dynamicClientCertSource, cancel := http_client.StartDynamicFileClientCertificateSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), clientCertPath, clientKeyPath)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
		http_client.TLSDynamicClientCertificate(dynamicClientCertSource),
	)
	if err != nil {
		t.Fatal(err)
	}

	{
		now := time.Now()
		clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, now.Add(-10*time.Second), now.Add(1*time.Second))
		clientCertPool := x509.NewCertPool()
		clientCertPool.AddCert(clientCert)
		_, _ = saveCertificate(t, tempDir, clientCertBytes, clientPriv)

		testServer := &http_client.Server{
			Config:       &http.Server{Handler: infoWriter()},
			TLS:          true,
			EnableHTTP2:  false,
			Certificates: []tls.Certificate{serverTlsCert},
			ClientCAs:    clientCertPool,
		}
		defer testServer.Start()()
		testUrl := testServer.URL

		checkResponse(t, c,
			&http.Request{
				URL: testUrl,
			},
			&http.Request{
				URL:        testUrl,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Accept-Encoding": []string{"gzip"},
					"User-Agent":      []string{"test"},
				},
			}, nil)
	}

	{
		clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
		clientCertPool := x509.NewCertPool()
		clientCertPool.AddCert(clientCert)
		_, _ = saveCertificate(t, tempDir, clientCertBytes, clientPriv)

		time.Sleep(2 * time.Second)

		testServer := &http_client.Server{
			Config:       &http.Server{Handler: infoWriter()},
			TLS:          true,
			EnableHTTP2:  false,
			Certificates: []tls.Certificate{serverTlsCert},
			ClientCAs:    clientCertPool,
		}
		defer testServer.Start()()
		testUrl := testServer.URL

		checkResponse(t, c,
			&http.Request{
				URL: testUrl,
			},
			&http.Request{
				URL:        testUrl,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Accept-Encoding": []string{"gzip"},
					"User-Agent":      []string{"test"},
				},
			}, nil)
	}
}

// TODO: add some extra dynamic client certificate tests (using fake timer etc.)

func TestDynamicRootCA(t *testing.T) {
	serverPriv, serverCertBytes, _ := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}
	serverCertPath, _ := saveCertificate(t, t.TempDir(), serverCertBytes, serverPriv)

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	dynamicRootCAs, cancel := http_client.StartDynamicFileRootCAsSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), serverCertPath)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.UserAgent("test"),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
		http_client.TLSDynamicRootCAs(dynamicRootCAs),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestDynamicRootCALate(t *testing.T) {
	serverPriv, serverCertBytes, _ := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}
	tempDir := t.TempDir()
	serverCertPath, _ := saveCertificate(t, tempDir, serverCertBytes, serverPriv)
	os.Remove(serverCertPath) // delete file, and recreate later

	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	testServer := &http_client.Server{
		Config:       &http.Server{Handler: infoWriter()},
		TLS:          true,
		EnableHTTP2:  false,
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
	}
	defer testServer.Start()()
	testUrl := testServer.URL

	dynamicRootCAs, cancel := http_client.StartDynamicFileRootCAsSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), serverCertPath)
	defer cancel()

	c, err := http_client.NewClient(
		http_client.UserAgent("test"),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
		http_client.TLSDynamicRootCAs(dynamicRootCAs),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		nil, func(err error) bool {
			return strings.Contains(err.Error(), "no such file or directory")
		})

	_, _ = saveCertificate(t, tempDir, serverCertBytes, serverPriv)

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestDynamicRootCARenew(t *testing.T) {
	clientPriv, clientCertBytes, clientCert := generateCaCertificate(t, nil, nil, boolPtr(true), []string{}, time.Time{}, time.Time{})
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert)
	clientTlsCert := &tls.Certificate{
		Certificate: [][]byte{clientCertBytes},
		PrivateKey:  clientPriv,
	}

	tempDir := t.TempDir()

	dynamic_rootca.CertCallbackRefreshDuration = 100 * time.Millisecond

	dynamicRootCAs, cancel := http_client.StartDynamicFileRootCAsSource(context.Background(), testr.NewWithOptions(t, testr.Options{
		Verbosity: 9,
	}), path.Join(tempDir, "cert.pem"))
	defer cancel()

	c, err := http_client.NewClient(
		http_client.UserAgent("test"),
		http_client.TLSClientCertificate(func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := cri.SupportsCertificate(clientTlsCert); err != nil {
				return nil, fmt.Errorf("cert is not accepted: %v", err)
			}

			return clientTlsCert, nil
		}),
		http_client.TLSDynamicRootCAs(dynamicRootCAs),
	)
	if err != nil {
		t.Fatal(err)
	}

	{
		serverPriv, serverCertBytes, _ := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
		serverTlsCert := tls.Certificate{
			Certificate: [][]byte{serverCertBytes},
			PrivateKey:  serverPriv,
		}
		_, _ = saveCertificate(t, tempDir, serverCertBytes, serverPriv)

		testServer := &http_client.Server{
			Config:       &http.Server{Handler: infoWriter()},
			TLS:          true,
			EnableHTTP2:  false,
			Certificates: []tls.Certificate{serverTlsCert},
			ClientCAs:    clientCertPool,
		}
		defer testServer.Start()()
		testUrl := testServer.URL

		checkResponse(t, c,
			&http.Request{
				URL: testUrl,
			},
			&http.Request{
				URL:        testUrl,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Accept-Encoding": []string{"gzip"},
					"User-Agent":      []string{"test"},
				},
			}, nil)
	}

	{
		serverPriv, serverCertBytes, _ := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
		serverTlsCert := tls.Certificate{
			Certificate: [][]byte{serverCertBytes},
			PrivateKey:  serverPriv,
		}
		_, _ = saveCertificate(t, tempDir, serverCertBytes, serverPriv)

		time.Sleep(200 * time.Millisecond)

		testServer := &http_client.Server{
			Config:       &http.Server{Handler: infoWriter()},
			TLS:          true,
			EnableHTTP2:  false,
			Certificates: []tls.Certificate{serverTlsCert},
			ClientCAs:    clientCertPool,
		}
		defer testServer.Start()()
		testUrl := testServer.URL

		checkResponse(t, c,
			&http.Request{
				URL: testUrl,
			},
			&http.Request{
				URL:        testUrl,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Accept-Encoding": []string{"gzip"},
					"User-Agent":      []string{"test"},
				},
			}, nil)
	}
}

func TestCustomClient(t *testing.T) {
	customTimeout := 103 * time.Second

	c, err := http_client.NewClient(
		http_client.ManualClient(&http.Client{
			Timeout: customTimeout,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	if c.Timeout != customTimeout {
		t.Fatalf("expected timeout %v, got %v instead", customTimeout, c.Timeout)
	}
}

func TestCustomTransport(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{}

	c, err := http_client.NewClient(
		http_client.ManualTransport(transport),
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}

func TestCustomTransportClone(t *testing.T) {
	serverPriv, serverCertBytes, serverCert := generateCaCertificate(t, nil, nil, boolPtr(false), []string{"127.0.0.1"}, time.Time{}, time.Time{})
	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(serverCert)
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertBytes},
		PrivateKey:  serverPriv,
	}

	testUrl, cancel := testTlsServerEnv(t, true, []tls.Certificate{serverTlsCert}, nil)
	defer cancel()

	transport := http.DefaultTransport.(*http.Transport).Clone()

	_, err := http_client.NewClient(
		http_client.ManualTransport(transport),
		http_client.EnableHttp2(false),
		http_client.TLSRootCAs(serverCertPool),
	)
	if err != nil {
		t.Fatal(err)
	}

	c, err := http_client.NewClient(
		http_client.ManualTransport(transport),
		http_client.TLSRootCAs(serverCertPool),
		http_client.UserAgent("test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	checkResponse(t, c,
		&http.Request{
			URL: testUrl,
		},
		&http.Request{
			URL:        testUrl,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
				"User-Agent":      []string{"test"},
			},
		}, nil)
}
