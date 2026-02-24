package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchRootHintsSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("root hints"))
	}))
	defer srv.Close()

	body, err := fetchRootHints(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchRootHints returned error: %v", err)
	}
	if string(body) != "root hints" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestFetchRootHintsUnexpectedHTTPStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := fetchRootHints(srv.Client(), srv.URL)
	if !errors.Is(err, ErrUnexpectedHTTPStatus) {
		t.Fatalf("error = %v, want %v", err, ErrUnexpectedHTTPStatus)
	}
}
