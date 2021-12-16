package acp

import (
	"net/http"
	"sync"
)

// httpHandler allows hot switching of http.ServeMux.
type httpHandler struct {
	handlerMu sync.RWMutex
	handler   http.Handler
}

// newHTTPHandler builds a new instance of httpHandler.
func newHTTPHandler() *httpHandler {
	return &httpHandler{
		handler: http.NotFoundHandler(),
	}
}

func (h *httpHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.handlerMu.RLock()
	handler := h.handler
	h.handlerMu.RUnlock()

	handler.ServeHTTP(rw, req)
}

// Update safely updates the current http.ServeMux with a new one.
func (h *httpHandler) Update(handler http.Handler) {
	if handler == nil {
		return
	}

	h.handlerMu.Lock()
	h.handler = handler
	h.handlerMu.Unlock()
}
