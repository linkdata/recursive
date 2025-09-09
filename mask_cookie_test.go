package recursive

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMaskCookie(t *testing.T) {
	full := "1234567890abcdef"
	if got := maskCookie(full); got != "12345678..." {
		t.Errorf("maskCookie(%q) = %q; want %q", full, got, "12345678...")
	}
	short := "abcd"
	if got := maskCookie(short); got != short {
		t.Errorf("maskCookie(%q) = %q; want %q", short, got, short)
	}
}

func TestCookieLogFormat(t *testing.T) {
	clicookie := "1234567890abcdef"
	srvcookie := "fedcba0987654321"
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, " COOKIE:c=%q s=%q", maskCookie(clicookie), maskCookie(srvcookie))
	want := " COOKIE:c=\"12345678...\" s=\"fedcba09...\""
	if got := buf.String(); got != want {
		t.Errorf("log output = %q; want %q", got, want)
	}
}
