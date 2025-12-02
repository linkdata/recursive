//go:build slowtest
// +build slowtest

package recursive

import (
	"bufio"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestCacheReadFromExistingBinaryRoundTrip(t *testing.T) {
	const fixture = "dnscache1.bin"
	t.Parallel()

	original, loadDuration, err := loadCacheFile(t, fixture)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s not present; skipping fixture round trip", fixture)
	}

	copyPath, writeDuration, err := saveCacheFile(t, original, "dnscache2-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(copyPath)

	copyCache, copyReadDuration, err := loadCacheFile(t, copyPath)
	if err != nil {
		t.Fatalf("ReadFrom(%s) returned error: %v", copyPath, err)
	}

	t.Logf("loaded %s in %s, wrote copy in %s, reloaded copy in %s", fixture, loadDuration, writeDuration, copyReadDuration)

	assertCachesEqual(t, original, copyCache)
}

func loadCacheFile(t *testing.T, fixture string) (c *Cache, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	var source *os.File
	if source, err = os.Open(fixture); err == nil {
		defer source.Close()
		c = NewCache()
		start := time.Now()
		var n int64
		n, err = c.ReadFrom(bufio.NewReader(source))
		elapsed = time.Since(start)
		if t != nil {
			t.Logf("loadCacheFile %q: %s (%v bytes)\n", fixture, elapsed, n)
		}
	}
	return
}

func saveCacheFileWriteTo(t *testing.T, fixture string, writeTo func(w io.Writer) (n int64, err error)) (fpath string, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	var f *os.File
	if f, err = os.CreateTemp("", fixture); err == nil {
		defer f.Close()
		fpath = f.Name()
		bw := bufio.NewWriter(f)
		defer bw.Flush()
		start := time.Now()
		var n int64
		n, err = writeTo(bw)
		elapsed = time.Since(start)
		if t != nil {
			t.Logf("saveCacheFile %q: %s (%v bytes)\n", fpath, elapsed, n)
		}
	}
	return
}

func saveCacheFile(t *testing.T, c *Cache, fixture string) (fpath string, elapsed time.Duration, err error) {
	if t != nil {
		t.Helper()
	}
	return saveCacheFileWriteTo(t, fixture, c.WriteTo)
}
