package recursive

import (
	"errors"
	"io"
)

var ErrWrongMagic = errors.New("wrong magic number")

const cacheMagic1 = int64(0xCACE0001)
const cacheMagic2 = int64(0xCACE0002)

func (cache *Cache) WriteTo(w io.Writer) (n int64, err error) {
	if cache != nil {
		err = cache.writeToV2(w, &n)
	}
	return
}

func (cache *Cache) ReadFrom(r io.Reader) (n int64, err error) {
	if cache != nil {
		var gotmagic int64
		if gotmagic, err = readInt64(r, &n); err == nil {
			err = ErrWrongMagic
			switch gotmagic {
			case cacheMagic1:
				err = cache.readFromV1(r, &n)
			case cacheMagic2:
				err = cache.readFromV2(r, &n)
			}
		}
	}
	return
}
