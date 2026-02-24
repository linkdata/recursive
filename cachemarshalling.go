package recursive

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

var ErrWrongMagic = errors.New("wrong magic number")
var ErrInvalidCacheEntry = errors.New("invalid cache entry")
var ErrCacheEntryTooLarge = errors.New("cache entry too large")

const cacheMagic = int64(0xCACE0003)
const marshalWorkerBufferSize = 1024 * 8
const maxCacheEntrySize = int(^uint16(0))

func (cache *Cache) lockAll() {
	for _, cq := range cache.cq {
		cq.mu.Lock()
	}
}

func (cache *Cache) unlockAll() {
	for _, cq := range cache.cq {
		cq.mu.Unlock()
	}
}

func (cache *Cache) WriteTo(w io.Writer) (n int64, err error) {
	if cache != nil {
		cache.lockAll()
		defer cache.unlockAll()
		err = cache.writeToLocked(w, &n)
	}
	return
}

func (cache *Cache) ReadFrom(r io.Reader) (n int64, err error) {
	if cache != nil {
		var gotmagic int64
		if gotmagic, err = readInt64(r, &n); err == nil {
			err = ErrWrongMagic
			if gotmagic == cacheMagic {
				err = cache.readFrom(r, &n)
			}
		}
	}
	return
}

func marshalWorker(qc *cacheBucket, w io.Writer, n *int64, perr *error, pmu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	var buf []byte
	wf := func() (fatal bool) {
		pmu.Lock()
		defer pmu.Unlock()
		written, err := writeAll(w, buf)
		*n += int64(written)
		if err != nil {
			fatal = (err == io.EOF || errors.Is(err, io.ErrShortWrite))
			*perr = errors.Join(*perr, err)
		}
		buf = buf[:0]
		return
	}
	for _, cv := range qc.cache {
		if b, err := cv.MarshalBinary(); err == nil {
			if len(b) > maxCacheEntrySize {
				pmu.Lock()
				*perr = errors.Join(*perr, ErrCacheEntryTooLarge)
				pmu.Unlock()
			} else if len(b) > 0 {
				if len(buf)+2+len(b) > marshalWorkerBufferSize {
					if wf() {
						return
					}
				}
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(b))) // #nosec G115
				buf = append(buf, b...)
			}
		} else {
			pmu.Lock()
			*perr = errors.Join(*perr, err)
			pmu.Unlock()
		}
	}
	wf()
}

func (cache *Cache) writeToLocked(w io.Writer, n *int64) (err error) {
	if err = writeInt64(w, n, cacheMagic); err == nil {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, cq := range cache.cq {
			wg.Add(1)
			go marshalWorker(cq, w, n, &err, &mu, &wg)
		}
		wg.Wait()
	}
	return
}

func (cache *Cache) readFrom(r io.Reader, n *int64) (err error) {
	cache.Clear()
	cache.lockAll()
	defer cache.unlockAll()
	var readerr error
	buf := make([]byte, 512)
	for readerr == nil {
		var numread int
		numread, readerr = io.ReadFull(r, buf[:2])
		*n += int64(numread)
		if readerr == nil {
			length := int(binary.BigEndian.Uint16(buf[:2]))
			if length > 0 {
				if length > cap(buf) {
					buf = make([]byte, length)
				}
				buf = buf[:length]
				numread, readerr = io.ReadFull(r, buf)
				*n += int64(numread)
				if readerr == nil {
					var cv cacheValue
					if merr := cv.UnmarshalBinary(buf); merr == nil {
						// the cache is explicitly allowed to contain expired entries
						// but may not contain entries without questions
						if cv.Msg != nil && len(cv.Question) > 0 {
							cache.cq[cv.bucketIndex()].setLocked(cv.Msg, cv.expires)
						} else {
							err = errors.Join(err, ErrInvalidCacheEntry)
						}
					} else {
						err = errors.Join(err, merr)
					}
				}
			}
		}
	}
	if readerr == io.EOF {
		readerr = nil
	}
	err = errors.Join(err, readerr)
	return
}
