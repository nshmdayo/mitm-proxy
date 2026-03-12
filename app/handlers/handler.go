package handlers

import "net/http"

// Handler processes intercepted HTTP requests and responses.
type Handler interface {
	Handle(req *http.Request, resp *http.Response)
}

// HandlerFunc is a function adapter that implements Handler.
type HandlerFunc func(*http.Request, *http.Response)

func (f HandlerFunc) Handle(req *http.Request, resp *http.Response) {
	f(req, resp)
}
