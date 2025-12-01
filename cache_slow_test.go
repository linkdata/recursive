//go:build slowtest
// +build slowtest

package recursive

import (
	"errors"
	"os"
	"testing"
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
