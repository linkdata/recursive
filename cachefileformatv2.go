package recursive

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

func errorWorker(perr *error, errch <-chan error) {
	for err := range errch {
		*perr = errors.Join(*perr, err)
	}
}

func marshalWorker(inch <-chan cacheValue, outch chan<- []byte, errch chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for cv := range inch {
		if b, err := cv.MarshalBinary(); err == nil {
			outch <- b
		} else {
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

func (cache *Cache) writeToV2(w io.Writer, n *int64) (err error) {
	if err = writeInt64(w, n, cacheMagic2); err == nil {
		var writewg sync.WaitGroup
		var marshalwg sync.WaitGroup
		numworkers := runtime.GOMAXPROCS(0)
		errch := make(chan error)
		inch := make(chan cacheValue, 1024)
		outch := make(chan []byte, 1024)
		go errorWorker(&err, errch)
		writewg.Add(1)
		go writeWorker(w, n, outch, errch, &writewg)
		for range numworkers {
			marshalwg.Add(1)
			go marshalWorker(inch, outch, errch, &marshalwg)
		}
		for _, cq := range cache.cq {
			cq.mu.RLock()
			for _, cv := range cq.cache {
				inch <- cv
			}
			cq.mu.RUnlock()
		}
		close(inch)
		marshalwg.Wait()
		close(outch)
		writewg.Wait()
		close(errch)
	}
	return
}

func (cache *Cache) readFromV2(r io.Reader, n *int64) (err error) {
	cache.Clear()
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
					if qtype := cv.Question[0].Qtype; qtype <= MaxQtype {
						cq := cache.cq[qtype]
						cq.mu.Lock()
						cq.setLocked(cv.Msg, cv.expires)
						cq.mu.Unlock()
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
