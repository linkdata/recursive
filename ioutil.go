package recursive

import (
	"encoding/binary"
	"io"
)

func readInt64(r io.Reader, numread *int64) (val int64, err error) {
	b := [8]byte{}
	var n int
	if n, err = io.ReadFull(r, b[:]); err == nil {
		err = io.ErrNoProgress
		if n == 8 {
			err = nil
			val = int64(binary.BigEndian.Uint64(b[:])) //#nosec
		}
	}
	*numread += int64(n)
	return
}

func writeInt64(w io.Writer, written *int64, val int64) (err error) {
	b := [8]byte{}
	binary.BigEndian.PutUint64(b[:], uint64(val)) //#nosec
	var n int
	if n, err = w.Write(b[:]); err == nil {
		err = io.ErrNoProgress
		if n == 8 {
			err = nil
		}
	}
	*written += int64(n)
	return
}

func readUint16(r io.Reader, numread *int64) (val uint16, err error) {
	b := [2]byte{}
	var n int
	if n, err = io.ReadFull(r, b[:]); err == nil {
		err = io.ErrNoProgress
		if n == 2 {
			err = nil
			val = uint16(binary.BigEndian.Uint16(b[:])) //#nosec
		}
	}
	*numread += int64(n)
	return
}

func writeUint16(w io.Writer, written *int64, val uint16) (err error) {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], val) //#nosec
	var n int
	if n, err = w.Write(b[:]); err == nil {
		err = io.ErrNoProgress
		if n == 2 {
			err = nil
		}
	}
	*written += int64(n)
	return
}
