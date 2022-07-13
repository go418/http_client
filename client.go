package http_client

import (
	"net/http"

	"github.com/go418/http-client/roundtrippers"
	"golang.org/x/net/http2"
)

type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

type OptionState struct {
	Dynamic *roundtrippers.DynamicTransportTripper
	H1root  *http.Transport
	H2root  *http2.Transport
	Client  *http.Client
}

type Option func(state *OptionState) error

func NewClientManual(options ...Option) (Client, error) {
	state := OptionState{}
	// reverse order of options (this way, the first option is hit first by a request)
	for i := len(options) - 1; i >= 0; i-- {
		if err := options[i](&state); err != nil {
			return nil, err
		}
	}
	return state.Client, nil
}

func NewClient(options ...Option) (Client, error) {
	fullLen := 3 + len(options)
	if len(options) > 0 {
		fullLen += 1
	}

	allOptions := make([]Option, 0, fullLen)
	if len(options) > 0 {
		// clone request to make sure the original request is not altered
		allOptions = append(allOptions, ManualCloneRequest())
	}
	allOptions = append(allOptions, options...)

	allOptions = append(allOptions,
		ManualDynamicClient(),
		ManualDefaultClient(),
		ManualDefaultTransport(),
	)

	return NewClientManual(allOptions...)
}
