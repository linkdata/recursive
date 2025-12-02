package recursive

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

const marshalWorkerBufferSize = 1024 * 64

func marshalWorker(qc *cacheBucket, w io.Writer, n *int64, perr *error, wlock *sync.Mutex, wg *sync.WaitGroup) {
	defer wg.Done()
	var buf []byte
	ef := func(e error) (fatal bool) {
		if e != nil {
			fatal = e == io.EOF || errors.Is(e, io.ErrShortWrite)
			wlock.Lock()
			*perr = errors.Join(*perr, e)
			wlock.Unlock()
		}
		return
	}
	wf := func() error {
		wlock.Lock()
		written, err := w.Write(buf)
		wlock.Unlock()
		buf = buf[:0]
		atomic.AndInt64(n, int64(written))
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
		var marshalwg sync.WaitGroup
		var wlock sync.Mutex
		for _, cq := range cache.cq {
			marshalwg.Add(1)
			go marshalWorker(cq, w, n, &err, &wlock, &marshalwg)
		}
		marshalwg.Wait()
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
						key := newBucketKey(question.Name, question.Qtype)
						cache.bucketFor(key).setLocked(key, cv.Msg, cv.expires)
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
