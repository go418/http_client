package roundtrippers

import "net/http"

type userAgentRoundTripper struct {
	userAgent string
	rt        http.RoundTripper
}

var _ RoundTripperWrapper = &userAgentRoundTripper{}

// NewUserAgentRoundTripper will add User-Agent header to a request unless it has already been set.
func NewUserAgentRoundTripper(userAgent string, rt http.RoundTripper) http.RoundTripper {
	return &userAgentRoundTripper{userAgent, rt}
}

func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("User-Agent")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req.Header.Set("User-Agent", rt.userAgent)
	return rt.rt.RoundTrip(req)
}

func (rt *userAgentRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}
