package errors

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type rawReporter struct {
	err *Error
}

func (r *rawReporter) Report(e *Error) {
	r.err = e
}

func TestAnonymousError(t *testing.T) {
	rr := &rawReporter{}
	Initialize("", rr, false)
	New("any error").Report()
	expected := &Error{
		Package: "errors",
		Func:    "TestAnonymousError",
		GoType:  "errors.Error",
		Desc:    "any error",
	}
	assert.Equal(t, expected.Error(), rr.err.Error(), "should log errors created by New()")

	Wrap(fmt.Errorf("any error")).Report()
	expected.GoType = "*errors.errorString"
	assert.Equal(t, expected.Error(), rr.err.Error(), "should log errors created by Wrap()")
}

func TestWrapNil(t *testing.T) {
	assert.Equal(t, nil, Wrap(nil).Source, "should have no error wrapping nil")
	assert.Equal(t, "", Wrap(nil).Desc, "should have nothing when wrapping nil")
}

func TestWrapAlreadyWrapped(t *testing.T) {
	e := New("any error")
	assert.Equal(t, e, Wrap(e), "should not wrap already wrapped error")
}

func TestWithFields(t *testing.T) {
	rr := &rawReporter{}
	Initialize("", rr, false)
	e := Wrap(errors.New("any error")).
		WithOp("test").
		ProxyType(NoProxy).
		ProxyAddr("a.b.c.d:80").
		OriginSite("www.google.com:443").
		URIScheme("https").
		UserAgent("Mozilla/5.0...").
		WithLocale().
		With("foo", "bar")
	e.Report()
	assert.NotEqual(t, rr.err.FileLine, rr.err.ReportFileLine, "should log all fields")
	expected := "any error Package=errors Func=TestWithFields GoType=*errors.errorString Op=test ProxyType=no_proxy ProxyAddr=a.b.c.d:80 OriginSite=www.google.com:443 URIScheme=https TimeZone=CST Language=CUserAgent=Mozilla/5.0... foo=bar"
	assert.Equal(t, expected, rr.err.Error(), "should log all fields")
}

func TestCaptureError(t *testing.T) {
	rr := &rawReporter{}
	Initialize("", rr, false)
	_, e := net.Dial("tcp", "an.non-existent.domain:80")
	err := Wrap(e)
	err.Report()
	expected := "no such host Package=errors Func=TestCaptureError GoType=net.DNSError Op=dial"
	assert.Contains(t, rr.err.Error(), expected, "should log dial error")
}

func TestCaptureHTTPError(t *testing.T) {
	rr := &rawReporter{}
	Initialize("", rr, false)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer ts.Close()

	_, e := http.Get(ts.URL)
	err := Wrap(e)
	err.Report()
	expected := &Error{
		Package: "errors",
		Func:    "TestCaptureHTTPError",
		GoType:  "url.Error",
		Desc:    "EOF",
		Op:      "Get",
	}
	assert.Equal(t, expected.Error(), rr.err.Error(), "should log http error")
}
