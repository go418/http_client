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

type ClientBuilder []Option

func (cb ClientBuilder) Add(options ...Option) ClientBuilder {
	return append(cb, options...)
}

func (cb ClientBuilder) Complete() (Client, error) {
	state := OptionState{}
	// reverse order of options (this way, the first option is hit first by a request)
	for i := len(cb) - 1; i >= 0; i-- {
		if err := cb[i](&state); err != nil {
			return nil, err
		}
	}
	return state.Client, nil
}

func NewClient(options ...Option) (Client, error) {
	builder := ClientBuilder(make([]Option, 0, 4+len(options)))

	return builder.
		Add(EnableOption(len(options) > 0, ManualCloneRequest())).
		Add(options...).
		Add(ManualDynamicClient()).
		Add(ManualDefaultClient()).
		Add(ManualDefaultTransport()).
		Complete()
}
