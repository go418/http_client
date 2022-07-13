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
	for _, wrapper := range options {
		if err := wrapper(&state); err != nil {
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
	allOptions = append(allOptions,
		ManualDefaultTransport(),
		ManualDefaultClient(),
		ManualDynamicClient(),
	)
	allOptions = append(allOptions, options...)
	if len(options) > 0 {
		allOptions = append(allOptions, ManualCloneRequest())
	}

	return NewClientManual(allOptions...)
}
