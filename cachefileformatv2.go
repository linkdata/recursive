package recursive

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

func errorWorker(perr *error, errch <-chan error) {
	for err := range errch {
		*perr = errors.Join(*perr, err)
	}
}

func marshalWorker(qc *cacheBucket, w io.Writer, n *int64, wlock *sync.Mutex, errch chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, cv := range qc.cache {
		b, err := cv.MarshalBinary()
		if err == nil {
			var buf []byte
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
			buf = append(buf, b...)
			var written int
			wlock.Lock()
			written, err = w.Write(buf)
			wlock.Unlock()
			atomic.AddInt64(n, int64(written))
		}
		if err != nil {
			errch <- err
		}
	}
}

func writeWorker(w io.Writer, n *int64, outch <-chan []byte, errch chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for b := range outch {
		if len(b) < 0xFFFF {
			var lenbuf [2]byte
			binary.BigEndian.PutUint16(lenbuf[:], uint16(len(b)))
			written, err := w.Write(lenbuf[:])
			atomic.AddInt64(n, int64(written))
			if err == nil {
				written, err = w.Write(b)
				atomic.AddInt64(n, int64(written))
			}
			if err != nil {
				errch <- err
			}
		}
	}
}

func (cache *Cache) writeToV2Locked(w io.Writer, n *int64) (err error) {
	if err = writeInt64(w, n, cacheMagic2); err == nil {
		var marshalwg sync.WaitGroup
		errch := make(chan error)
		go errorWorker(&err, errch)
		var wlock sync.Mutex
		for _, cq := range cache.cq {
			marshalwg.Add(1)
			go marshalWorker(cq, w, n, &wlock, errch, &marshalwg)
		}
		marshalwg.Wait()
		close(errch)
	}
	return
}

func (cache *Cache) readFromV2Locked(r io.Reader, n *int64) (err error) {
	cache.clearLocked()
	for err == nil {
		var buf [0xFFFF]byte
		var numread int
		if numread, err = io.ReadFull(r, buf[:2]); err == nil {
			*n += int64(numread)
			length := int(binary.BigEndian.Uint16(buf[:2]))
			if numread, err = io.ReadFull(r, buf[:length]); err == nil {
				*n += int64(numread)
				var cv cacheValue
				if err = cv.UnmarshalBinary(buf[:length]); err == nil {
					if len(cv.Question) > 0 {
						question := cv.Question[0]
						var key bucketKey
						var ok bool
						if key, ok = newBucketKey(question.Name, question.Qtype); ok {
							cache.bucketFor(key).setLocked(key, cv.Msg, cv.expires)
						}
					}
				}
			}
		}
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return
}
