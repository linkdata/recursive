package recursive

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const marshalWorkerBufferSize = 1024 * 64

func marshalWorker(qc *cacheBucket, w io.Writer, n *int64, perr *error, pmu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	var buf []byte
	ef := func(e error) (fatal bool) {
		if e != nil {
			fatal = e == io.EOF || errors.Is(e, io.ErrShortWrite)
			pmu.Lock()
			*perr = errors.Join(*perr, e)
			pmu.Unlock()
		}
		return
	}
	wf := func() error {
		pmu.Lock()
		written, err := w.Write(buf)
		*n += int64(written)
		pmu.Unlock()
		buf = buf[:0]
		return err
	}
	for _, cv := range qc.cache {
		b, err := cv.MarshalBinary()
		if !ef(err) {
			if len(buf)+2+len(b) > marshalWorkerBufferSize {
				if ef(wf()) {
					return
				}
			}
			buf = binary.BigEndian.AppendUint16(buf, uint16(cv.bucketIndex())) // #nosec G115
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))           // #nosec G115
			buf = append(buf, b...)
		}
	}
	ef(wf())
}

func (cache *Cache) writeToV2Locked(w io.Writer, n *int64) (err error) {
	if err = writeInt64(w, n, cacheMagic2); err == nil {
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

func (cache *Cache) unmarshalWorker(cq *cacheBucket, ch <-chan *sliceRef, pool *sync.Pool, perr *error, pmu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	for sr := range ch {
		var err error
		var cv cacheValue
		if err = cv.UnmarshalBinary(sr.b); err == nil {
			if len(cv.Question) > 0 {
				cq.setLocked(cv.Msg, cv.expires)
			}
		} else {
			pmu.Lock()
			*perr = errors.Join(*perr, err)
			pmu.Unlock()
		}
		pool.Put(sr)
	}
}

type sliceRef struct {
	b []byte
}

func (cache *Cache) readFromV2Locked(r io.Reader, n *int64) (err error) {
	cache.clearLocked()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rdchans [cacheBucketCount]chan *sliceRef
	var bufPool = sync.Pool{
		New: func() any {
			// The Pool's New function should generally only return pointer
			// types, since a pointer can be put into the return interface
			// value without an allocation:
			return &sliceRef{b: make([]byte, 512)}
		},
	}
	for i := range rdchans {
		rdchans[i] = make(chan *sliceRef, 1024)
		wg.Add(1)
		go cache.unmarshalWorker(cache.cq[i], rdchans[i], &bufPool, &err, &mu, &wg)
	}
	var readerr error
	for readerr == nil {
		sr := bufPool.Get().(*sliceRef)
		var numread int
		numread, readerr = io.ReadFull(r, sr.b[:4])
		*n += int64(numread)
		if readerr == nil {
			bucketIdx := int(binary.BigEndian.Uint16(sr.b[:2]))
			length := int(binary.BigEndian.Uint16(sr.b[2:]))
			if length > cap(sr.b) {
				sr.b = make([]byte, length)
			}
			sr.b = sr.b[:length]
			numread, readerr = io.ReadFull(r, sr.b)
			*n += int64(numread)
			if err == nil {
				rdchans[bucketIdx] <- sr
			}
		}
	}
	for _, ch := range rdchans {
		close(ch)
	}
	wg.Wait()
	if readerr == io.EOF {
		readerr = nil
	}
	return
}
