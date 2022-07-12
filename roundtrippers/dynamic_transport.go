package roundtrippers

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type TransportUpdater func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error)

type DynamicTransportTripper struct {
	rt              atomic.Value
	updateTransport []TransportUpdater
}

var _ http.RoundTripper = &DynamicTransportTripper{}

func NewDynamicTransportTripper(rt *http.Transport) *DynamicTransportTripper {
	dtt := &DynamicTransportTripper{}
	dtt.rt.Store(rt)
	return dtt
}

func (rt *DynamicTransportTripper) RegisterTransportUpdater(fn TransportUpdater) {
	rt.updateTransport = append(rt.updateTransport, fn)
}

func (rt *DynamicTransportTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(rt.updateTransport) == 0 {
		return rt.rt.Load().(*http.Transport).RoundTrip(req)
	}

	isClone := false
	transport := rt.rt.Load().(*http.Transport)

	for _, updater := range rt.updateTransport {
		if newTransport, err := updater(req, transport, isClone); err != nil {
			return nil, err
		} else if newTransport == nil {
			return nil, fmt.Errorf("registerd transport updater did not return a valid *http.Transport")
		} else {
			isClone = isClone || (transport != newTransport) // check if returned transport is a clone
			transport = newTransport
		}
	}

	if isClone {
		rt.rt.Store(transport)
	}

	return transport.RoundTrip(req)
}
