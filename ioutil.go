package recursive

import (
	"encoding/binary"
	"io"
)

func readInt64(r io.Reader, numread *int64) (val int64, err error) {
	b := [8]byte{}
	var n int
	if n, err = io.ReadFull(r, b[:]); err == nil {
		val = int64(binary.BigEndian.Uint64(b[:])) //#nosec
	}
	*numread += int64(n)
	return
}

func writeInt64(w io.Writer, written *int64, val int64) (err error) {
	b := [8]byte{}
	binary.BigEndian.PutUint64(b[:], uint64(val)) //#nosec
	var n int
	n, err = writeAll(w, b[:])
	*written += int64(n)
	return
}

func writeAll(w io.Writer, p []byte) (n int, err error) {
	for len(p) > 0 && err == nil {
		var written int
		written, err = w.Write(p)
		n += written
		if err == nil {
			if written > 0 {
				p = p[written:]
			} else {
				err = io.ErrShortWrite
			}
		}
	}
	return
}
