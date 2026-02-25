package main

import (
	"context"
	"errors"
	"os"
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

const testWGConfig = `[Interface]
PrivateKey = AEnvL9tVr+7JF0sMVjjzPjIxrrc/hoVJ5B82WWpVamI=
Address = 10.131.132.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = Wh3yY7/fE3fyHJ8TOwLJ//CIRbgrlVl4bLQ+npNBSRU=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
`

func TestNewWireGuardDialerWithoutConfig(t *testing.T) {
	t.Parallel()

	dialer, closer, err := newWireGuardDialer("")
	if err != nil {
		t.Fatalf("newWireGuardDialer returned error for empty config: %v", err)
	}
	if dialer != nil {
		t.Fatalf("expected nil dialer for empty config, got %T", dialer)
	}
	if closer != nil {
		t.Fatalf("expected nil closer for empty config, got %T", closer)
	}
}

func TestNewWireGuardDialerMissingConfigFile(t *testing.T) {
	t.Parallel()

	_, _, err := newWireGuardDialer("/missing/wireguard.conf")
	if !errors.Is(err, ErrOpenWireGuardConfig) {
		t.Fatalf("expected ErrOpenWireGuardConfig, got %v", err)
	}
}

func TestNewWireGuardDialerInvalidConfigFile(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "wg-invalid-*.conf")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	if _, err = file.WriteString("not a wireguard config"); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, _, err = newWireGuardDialer(file.Name())
	if !errors.Is(err, ErrParseWireGuardConfig) {
		t.Fatalf("expected ErrParseWireGuardConfig, got %v", err)
	}
}

func TestNewWireGuardDialerWithValidConfigFile(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "wg-valid-*.conf")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	if _, err = file.WriteString(testWGConfig); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	dialer, closer, err := newWireGuardDialer(file.Name())
	if err != nil {
		t.Fatalf("newWireGuardDialer returned error: %v", err)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer for valid config")
	}
	if closer == nil {
		t.Fatal("expected non-nil closer for valid config")
	}
	if err = closer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
