package http_client

import (
	"net/http"

	"github.com/go418/http_client/roundtrippers"
)

type OptionState struct {
	Dynamic *roundtrippers.DynamicTransportTripper
	Client  *http.Client
}

type Option func(state *OptionState) error

type ClientBuilder []Option

func (cb ClientBuilder) Add(options ...Option) ClientBuilder {
	return append(cb, options...)
}

func (cb ClientBuilder) Complete() (*http.Client, error) {
	state := OptionState{}

	state.Dynamic = roundtrippers.NewDynamicTransportTripper()
	state.Client = &http.Client{Transport: state.Dynamic}

	// reverse order of options (this way, the first transport is hit first by a request)
	for i := len(cb) - 1; i >= 0; i-- {
		if err := cb[i](&state); err != nil {
			return nil, err
		}
	}

	// Register a default transport, in case no explicit transport was provided
	if err := DefaultTransport()(&state); err != nil {
		return nil, err
	}

	if len(cb) > 0 {
		if err := ManualCloneRequest()(&state); err != nil {
			return nil, err
		}
	}

	return state.Client, nil
}

func NewClient(options ...Option) (*http.Client, error) {
	return ClientBuilder(options).Complete()
}
