package recursive

import (
	"errors"
	"io"
)

var ErrWrongMagic = errors.New("wrong magic number")

const cacheMagic1 = int64(0xCACE0001)
const cacheMagic2 = int64(0xCACE0002)

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
		err = cache.writeToV2Locked(w, &n)
	}
	return
}

func (cache *Cache) ReadFrom(r io.Reader) (n int64, err error) {
	if cache != nil {
		cache.lockAll()
		defer cache.unlockAll()
		var gotmagic int64
		if gotmagic, err = readInt64(r, &n); err == nil {
			err = ErrWrongMagic
			switch gotmagic {
			case cacheMagic1:
				err = cache.readFromV1Locked(r, &n)
			case cacheMagic2:
				err = cache.readFromV2Locked(r, &n)
			}
		}
	}
	return
}
