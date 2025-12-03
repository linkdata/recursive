package recursive

import (
	"bytes"
	"testing"
)

const benchmarkCacheEntries = 1_000_000

func BenchmarkCacheWriteToMillionEntries(b *testing.B) {
	cache := newCacheWithEntries(b, benchmarkCacheEntries)
	if entries := cache.Entries(); entries != benchmarkCacheEntries {
		b.Fatalf("cache entry count = %d, want %d", entries, benchmarkCacheEntries)
	}

	buf, written := mustWriteCacheToBuffer(b, cache)

	b.ReportAllocs()
	b.SetBytes(int64(buf.Len()))

	var err error
	for b.Loop() {
		buf.Reset()
		written, err = cache.WriteTo(&buf)
		if err != nil {
			b.Fatalf("WriteTo returned error: %v", err)
		}
		if int64(buf.Len()) != written {
			b.Fatalf("WriteTo length mismatch: buf=%d reported=%d", buf.Len(), written)
		}
	}
}

func BenchmarkCacheReadFromMillionEntries(b *testing.B) {
	cache := newCacheWithEntries(b, benchmarkCacheEntries)
	if entries := cache.Entries(); entries != benchmarkCacheEntries {
		b.Fatalf("cache entry count = %d, want %d", entries, benchmarkCacheEntries)
	}

	buf, written := mustWriteCacheToBuffer(b, cache)

	data := buf.Bytes()
	if len(data) == 0 {
		b.Fatalf("buffer length = %d after initial write", len(data))
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		dst := NewCache()
		reader := bytes.NewReader(data)
		read, readErr := dst.ReadFrom(reader)
		if readErr != nil {
			b.Fatalf("ReadFrom returned error: %v", readErr)
		}
		if read != written {
			b.Fatalf("ReadFrom read %d bytes, want %d", read, written)
		}
	}
}
