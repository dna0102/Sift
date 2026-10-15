package scan

import (
	"context"
	"net/http"
)

type Request struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
	Route   string
	Profile string
	Tag     string
}

type Response struct {
	Status   int
	Header   http.Header
	Body     []byte
	Proto    string
	Duration int64
	FlowID   int64
	Err      string
}

type Requester interface {
	Do(ctx context.Context, r *Request) (*Response, error)
}
