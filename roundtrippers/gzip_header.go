package roundtrippers

import "net/http"

type gzipHeaderRoundTripper struct {
	rt http.RoundTripper
}

var _ RoundTripperWrapper = gzipHeaderRoundTripper{}

// NewGzipHeaderRoundTripper
func NewGzipHeaderRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return &gzipHeaderRoundTripper{rt}
}

func (rt gzipHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   https://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		req.Header.Set("Accept-Encoding", "gzip")
	}

	return rt.rt.RoundTrip(req)
}

func (rt gzipHeaderRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}
