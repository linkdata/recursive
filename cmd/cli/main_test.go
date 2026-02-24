package main

import (
	"context"
	"testing"
	"time"

	"github.com/linkdata/recursive"
)

func TestSetResolverQueryTimeout(t *testing.T) {
	t.Parallel()

	rec := recursive.NewWithOptions(nil, nil, nil, nil, nil)
	original := rec.Timeout

	setResolverQueryTimeout(rec, 7)
	if rec.Timeout != 7*time.Second {
		t.Fatalf("timeout = %v, want %v", rec.Timeout, 7*time.Second)
	}

	setResolverQueryTimeout(rec, 0)
	if rec.Timeout != 7*time.Second {
		t.Fatalf("timeout changed on zero input, got %v", rec.Timeout)
	}

	setResolverQueryTimeout(nil, 5)
	if original <= 0 {
		t.Fatalf("unexpected original timeout %v", original)
	}
}

func TestNewPerQueryContextDoesNotInheritParentCancellation(t *testing.T) {
	t.Parallel()

	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	ctx, cancel := newPerQueryContext(parent, 150)
	defer cancel()

	if err := ctx.Err(); err != nil {
		t.Fatalf("query context canceled immediately: %v", err)
	}
	if _, ok := ctx.Deadline(); !ok {
		t.Fatalf("query context missing deadline")
	}
}

func TestNewPerQueryContextWithoutTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := newPerQueryContext(context.Background(), 0)
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Fatalf("unexpected deadline for zero maxwait")
	}
}
