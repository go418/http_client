package roundtrippers

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

type TransportCreator func(transport *http.Transport, isClone bool) (*http.Transport, bool, error)
type TransportUpdater func(req *http.Request, transport *http.Transport, isClone bool) (*http.Transport, error)

type DynamicTransportTripper struct {
	rt                          atomic.Value
	mu                          sync.Mutex
	reverseCreateTransportSteps []TransportCreator
	reverseUpdateTransportSteps []TransportUpdater
}

var _ RoundTripperWrapper = &DynamicTransportTripper{}

func NewDynamicTransportTripper() *DynamicTransportTripper {
	return &DynamicTransportTripper{}
}

func (rt *DynamicTransportTripper) RegisterTransportCreator(fn TransportCreator) {
	rt.reverseCreateTransportSteps = append(rt.reverseCreateTransportSteps, fn)
}

func (rt *DynamicTransportTripper) RegisterTransportUpdater(fn TransportUpdater) {
	rt.reverseUpdateTransportSteps = append(rt.reverseUpdateTransportSteps, fn)
}

func (rt *DynamicTransportTripper) lazyCreateTransport() (*http.Transport, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if transport, ok := rt.rt.Load().(*http.Transport); ok {
		return transport, nil // prevent creating the transport multiple times in parallel
	}

	isClone := false
	var transport *http.Transport = nil

	for i := len(rt.reverseCreateTransportSteps) - 1; i >= 0; i-- {
		if newTransport, newIsClone, err := rt.reverseCreateTransportSteps[i](transport, isClone); err != nil {
			return nil, err
		} else if newTransport == nil {
			return nil, fmt.Errorf("registerd transport creator did not return a valid *http.Transport")
		} else {
			isClone = newIsClone
			transport = newTransport
		}
	}

	rt.reverseCreateTransportSteps = nil // clear array

	transport.CloseIdleConnections() // close idle connections from existing transport
	rt.rt.Store(transport)

	return transport, nil
}

func (rt *DynamicTransportTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, ok := rt.rt.Load().(*http.Transport)

	if !ok {
		var err error
		if transport, err = rt.lazyCreateTransport(); err != nil {
			return nil, err
		}
	}

	isClone := false

	oldTransport := transport

	for i := len(rt.reverseUpdateTransportSteps) - 1; i >= 0; i-- {
		if newTransport, err := rt.reverseUpdateTransportSteps[i](req, transport, isClone); err != nil {
			return nil, err
		} else if newTransport == nil {
			return nil, fmt.Errorf("registerd transport updater did not return a valid *http.Transport")
		} else {
			isClone = isClone || (transport != newTransport) // check if returned transport is a clone
			transport = newTransport
		}
	}

	if isClone {
		if oldTransport != nil {
			oldTransport.CloseIdleConnections()
		}
		rt.rt.Store(transport)
	}

	return transport.RoundTrip(req)
}

func (rt *DynamicTransportTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt.Load().(*http.Transport)
}

func (rt *DynamicTransportTripper) CloseIdleConnections() {
	if transport, ok := rt.rt.Load().(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
