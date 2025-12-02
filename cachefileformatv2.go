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
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
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

func (cache *Cache) unmarshalWorker(r io.Reader, n *int64, perr *error, pmu *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	var err error
	buf := make([]byte, 512)
	ef := func(e error) (fatal bool) {
		if e != nil {
			fatal = e == io.EOF || errors.Is(e, io.ErrShortWrite)
			if e != io.EOF {
				pmu.Lock()
				*perr = errors.Join(*perr, e)
				pmu.Unlock()
			}
		}
		return
	}
	rf := func() (length int, err error) {
		pmu.Lock()
		defer pmu.Unlock()
		var numread int
		numread, err = io.ReadFull(r, buf[:2])
		*n += int64(numread)
		if err == nil {
			length = int(binary.BigEndian.Uint16(buf[:2]))
			if length > len(buf) {
				buf = make([]byte, length)
			}
			numread, err = io.ReadFull(r, buf[:length])
			*n += int64(numread)
		}
		return
	}
	for !ef(err) {
		var length int
		if length, err = rf(); err == nil {
			var cv cacheValue
			if err = cv.UnmarshalBinary(buf[:length]); err == nil {
				if len(cv.Question) > 0 {
					question := cv.Question[0]
					key := newBucketKey(question.Name, question.Qtype)
					cache.bucketFor(key).set(key, cv.Msg, cv.expires)
				}
			}
		}
	}
}

func (cache *Cache) readFromV2(r io.Reader, n *int64) (err error) {
	cache.Clear()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range cacheBucketCount {
		wg.Add(1)
		go cache.unmarshalWorker(r, n, &err, &mu, &wg)
	}
	wg.Wait()
	return
}
