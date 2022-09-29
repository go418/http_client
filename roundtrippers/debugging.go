package roundtrippers

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

// requestInfo keeps track of information about a request/response combination
type requestInfo struct {
	RequestHeaders http.Header `datapolicy:"token"`
	RequestVerb    string
	RequestURL     string

	ResponseStatus  string
	ResponseHeaders http.Header
	ResponseErr     error

	muTrace          sync.Mutex // Protect trace fields
	DNSLookup        time.Duration
	Dialing          time.Duration
	GetConnection    time.Duration
	TLSHandshake     time.Duration
	ServerProcessing time.Duration
	ConnectionReused bool

	Duration time.Duration
}

// newRequestInfo creates a new RequestInfo based on an http request
func newRequestInfo(req *http.Request) *requestInfo {
	return &requestInfo{
		RequestURL:     req.URL.String(),
		RequestVerb:    req.Method,
		RequestHeaders: req.Header,
	}
}

// complete adds information about the response to the requestInfo
func (r *requestInfo) complete(response *http.Response, err error) {
	if err != nil {
		r.ResponseErr = err
		return
	}
	r.ResponseStatus = response.Status
	r.ResponseHeaders = response.Header
}

var requestId uint64 = 0

// debuggingRoundTripper will display information about the requests passing
// through it based on what is configured
type debuggingRoundTripper struct {
	rt  http.RoundTripper
	log logr.Logger
}

var _ RoundTripperWrapper = &debuggingRoundTripper{}

// NewDebuggingRoundTripper allows to display in the logs output debug information
// on the API requests performed by the client.
func NewDebuggingRoundTripper(log logr.Logger, rt http.RoundTripper) http.RoundTripper {
	return &debuggingRoundTripper{
		rt:  rt,
		log: log,
	}
}

var knownAuthTypes = map[string]bool{
	"bearer":    true,
	"basic":     true,
	"negotiate": true,
}

// maskValue masks credential content from authorization headers
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
func maskValue(key string, value string) string {
	if !strings.EqualFold(key, "Authorization") {
		return value
	}
	if len(value) == 0 {
		return ""
	}
	var authType string
	if i := strings.Index(value, " "); i > 0 {
		authType = value[0:i]
	} else {
		authType = value
	}
	if !knownAuthTypes[strings.ToLower(authType)] {
		return "<masked>"
	}
	if len(value) > len(authType)+1 {
		value = authType + " <masked>"
	} else {
		value = authType
	}
	return value
}

var DebugBodyChunkLength = 100

// Level 5: log HTTP basic info
// Level 6: log HTTP headers
// Level 7: log HTTP body
// Level 8: log HTTP timings
// Level 9: log HTTP trace details
func (rt *debuggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqInfo := newRequestInfo(req)

	requestId := atomic.AddUint64(&requestId, 1)
	log := rt.log.WithName(fmt.Sprintf("request-%d", requestId))

	log.V(5).Info(
		"HTTP request",
		"verb", reqInfo.RequestVerb,
		"url", reqInfo.RequestURL,
	)
	log.V(6).Info("HTTP request: headers", extractHeaders(reqInfo.RequestHeaders)...)

	if log.V(7).Enabled() {
		req.Body = newBodyLogTeeReader(
			req.Body,
			DebugBodyChunkLength,
			func(b []byte) {
				if len(b) == 0 {
					return
				}
				log.V(7).Info("HTTP request: body", "body", string(b))
			},
		)
	}

	startTime := time.Now()

	if log.V(8).Enabled() {
		var getConn, dnsStart, dialStart, tlsStart, serverStart time.Time
		var host string
		trace := &httptrace.ClientTrace{
			// DNS
			DNSStart: func(info httptrace.DNSStartInfo) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				dnsStart = time.Now()
				host = info.Host
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				reqInfo.DNSLookup = time.Since(dnsStart)
				log.V(9).Info("HTTP trace: DNS lookup", "host", host, "resolved", info.Addrs)
			},
			// Dial
			ConnectStart: func(network, addr string) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				dialStart = time.Now()
			},
			ConnectDone: func(network, addr string, err error) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				reqInfo.Dialing = time.Since(dialStart)
				if err != nil {
					log.V(9).Info("HTTP trace: dial", "network", network, "key", addr, "status", "failed", "error", err)
				} else {
					log.V(9).Info("HTTP trace: dial", "network", network, "key", addr, "status", "success")
				}
			},
			// TLS
			TLSHandshakeStart: func() {
				tlsStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				reqInfo.TLSHandshake = time.Since(tlsStart)
			},
			// Connection (it can be DNS + Dial or just the time to get one from the connection pool)
			GetConn: func(hostPort string) {
				getConn = time.Now()
			},
			GotConn: func(info httptrace.GotConnInfo) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				reqInfo.GetConnection = time.Since(getConn)
				reqInfo.ConnectionReused = info.Reused
			},
			// Server Processing (time since we wrote the request until first byte is received)
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				serverStart = time.Now()
			},
			GotFirstResponseByte: func() {
				reqInfo.muTrace.Lock()
				defer reqInfo.muTrace.Unlock()
				reqInfo.ServerProcessing = time.Since(serverStart)
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	response, err := rt.rt.RoundTrip(req)
	reqInfo.Duration = time.Since(startTime)

	reqInfo.complete(response, err)

	log.V(5).Info(
		"HTTP response",
		"verb", reqInfo.RequestVerb,
		"url", reqInfo.RequestURL,
		"status", reqInfo.ResponseStatus,
		"duration (ms)", reqInfo.Duration.Nanoseconds()/int64(time.Millisecond),
	)

	if log.V(8).Enabled() {
		stats := []interface{}{}
		if !reqInfo.ConnectionReused {
			stats = append(stats,
				"DNS lookup (ms)", reqInfo.DNSLookup.Nanoseconds()/int64(time.Millisecond),
				"dial (ms)", reqInfo.Dialing.Nanoseconds()/int64(time.Millisecond),
				"TLS handshake (ms)", reqInfo.TLSHandshake.Nanoseconds()/int64(time.Millisecond),
			)
		} else {
			stats = append(stats, "GetConnection (ms)", reqInfo.GetConnection.Nanoseconds()/int64(time.Millisecond))
		}
		if reqInfo.ServerProcessing != 0 {
			stats = append(stats, "ServerProcessing (ms)", reqInfo.ServerProcessing.Nanoseconds()/int64(time.Millisecond))
		}
		stats = append(stats, "duration (ms)", reqInfo.Duration.Nanoseconds()/int64(time.Millisecond))

		log.V(8).Info("HTTP response: statistics", stats...)
	}

	log.V(6).Info("HTTP response: headers", extractHeaders(reqInfo.ResponseHeaders)...)

	if log.V(7).Enabled() && response != nil {
		response.Body = newBodyLogTeeReader(
			response.Body,
			DebugBodyChunkLength,
			func(b []byte) {
				if len(b) == 0 {
					return
				}
				log.V(7).Info("HTTP response: body", "body", string(b))
			},
		)
	}

	return response, err
}

func newBodyLogTeeReader(body io.ReadCloser, flushlimit int, log func(b []byte)) io.ReadCloser {
	if body == nil {
		return nil
	}

	return &bodyLogTeeReader{
		log:        log,
		flushlimit: flushlimit,
		body:       body,
	}
}

type bodyLogTeeReader struct {
	log        func(b []byte)
	buffer     []byte
	flushlimit int
	body       io.ReadCloser
}

func (w *bodyLogTeeReader) flush() {
	w.log(w.buffer)
	w.buffer = w.buffer[:0]
}

func (w *bodyLogTeeReader) Close() error {
	w.flush()
	return w.body.Close()
}

func (w *bodyLogTeeReader) Read(b []byte) (int, error) {
	n, err := w.body.Read(b)
	if err != nil {
		return n, err
	}
	w.buffer = append(w.buffer, b[:n]...)
	if len(w.buffer) >= w.flushlimit {
		w.flush()
	}
	return n, err
}

func (rt *debuggingRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}

func extractHeaders(headers http.Header) []interface{} {
	flat := []interface{}{}
	for key, values := range headers {
		for _, value := range values {
			value = maskValue(key, value)
			flat = append(flat, key, value)
		}
	}
	return flat
}
