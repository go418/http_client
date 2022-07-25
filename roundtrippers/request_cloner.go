package roundtrippers

import "net/http"

type requestClonerRoundTripper struct {
	rt http.RoundTripper
}

var _ RoundTripperWrapper = requestClonerRoundTripper{}

func NewRequestClonerRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return &requestClonerRoundTripper{rt}
}

func (rt requestClonerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqClone := cloneRequest(req)

	return rt.rt.RoundTrip(reqClone)
}

func (rt requestClonerRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}

// CloneRequest creates a shallow copy of the request along with a deep copy of the Headers.
func cloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)

	// shallow clone
	*r = *req

	// deep copy headers
	r.Header = cloneHeader(req.Header)

	return r
}

// CloneHeader creates a deep copy of an http.Header.
func cloneHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}
