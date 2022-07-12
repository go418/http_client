package http_client

import (
	"net/http"

	"github.com/go418/http-client/roundtrippers"
	"golang.org/x/net/http2"
)

type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

type optionState struct {
	dynamic *roundtrippers.DynamicTransportTripper
	h1root  *http.Transport
	h2root  *http2.Transport
	client  *http.Client
}

type Option func(state *optionState) error

func NewClient(options ...Option) (Client, error) {
	state := optionState{}
	if err := defaultClient()(&state); err != nil {
		return nil, err
	}
	if err := dynamicClient()(&state); err != nil {
		return nil, err
	}
	for _, wrapper := range options {
		if err := wrapper(&state); err != nil {
			return nil, err
		}
	}
	if len(options) > 0 {
		if err := cloneRequest()(&state); err != nil {
			return nil, err
		}
	}
	return state.client, nil
}
