package roundtrippers

import "net/http"

type requestClonerRoundTripper struct {
	next http.RoundTripper
}

func NewRequestClonerRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return &requestClonerRoundTripper{rt}
}

func (rcrt requestClonerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqClone := CloneRequest(req)

	return rcrt.next.RoundTrip(reqClone)
}

// CloneRequest creates a shallow copy of the request along with a deep copy of the Headers.
func CloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)

	// shallow clone
	*r = *req

	// deep copy headers
	r.Header = CloneHeader(req.Header)

	return r
}

// CloneHeader creates a deep copy of an http.Header.
func CloneHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}
