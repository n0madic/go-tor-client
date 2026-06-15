// Package byteutil provides small big-endian and buffer helpers used across
// the Tor client. It deliberately keeps no protocol knowledge.
package byteutil

import "encoding/binary"

// Writer is an append-only big-endian byte builder. The zero value is ready to
// use. It never returns errors; callers build a buffer and read Bytes().
type Writer struct {
	buf []byte
}

// NewWriter returns a Writer with the given initial capacity hint.
func NewWriter(capacityHint int) *Writer {
	return &Writer{buf: make([]byte, 0, capacityHint)}
}

// Len reports how many bytes have been written.
func (w *Writer) Len() int { return len(w.buf) }

// Bytes returns the accumulated buffer. The slice aliases internal storage.
func (w *Writer) Bytes() []byte { return w.buf }

// Byte appends a single byte.
func (w *Writer) Byte(b byte) *Writer {
	w.buf = append(w.buf, b)
	return w
}

// U16 appends a big-endian uint16.
func (w *Writer) U16(v uint16) *Writer {
	w.buf = binary.BigEndian.AppendUint16(w.buf, v)
	return w
}

// U32 appends a big-endian uint32.
func (w *Writer) U32(v uint32) *Writer {
	w.buf = binary.BigEndian.AppendUint32(w.buf, v)
	return w
}

// U64 appends a big-endian uint64.
func (w *Writer) U64(v uint64) *Writer {
	w.buf = binary.BigEndian.AppendUint64(w.buf, v)
	return w
}

// Bytes appends raw bytes.
func (w *Writer) Write(p []byte) *Writer {
	w.buf = append(w.buf, p...)
	return w
}

// Reader is a big-endian sequential reader over a byte slice. Read methods
// report whether enough bytes remained; once a read fails the reader is marked
// errored and subsequent reads also fail.
type Reader struct {
	buf []byte
	pos int
	err bool
}

// NewReader wraps b for sequential reading.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Err reports whether any read has run past the end of the buffer.
func (r *Reader) Err() bool { return r.err }

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// Byte reads one byte.
func (r *Reader) Byte() byte {
	if r.err || r.pos+1 > len(r.buf) {
		r.err = true
		return 0
	}
	b := r.buf[r.pos]
	r.pos++
	return b
}

// U16 reads a big-endian uint16.
func (r *Reader) U16() uint16 {
	if r.err || r.pos+2 > len(r.buf) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v
}

// U32 reads a big-endian uint32.
func (r *Reader) U32() uint32 {
	if r.err || r.pos+4 > len(r.buf) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v
}

// U64 reads a big-endian uint64.
func (r *Reader) U64() uint64 {
	if r.err || r.pos+8 > len(r.buf) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v
}

// Bytes reads exactly n bytes, returning a slice aliasing the underlying
// buffer. On underflow it marks the reader errored and returns nil.
func (r *Reader) Bytes(n int) []byte {
	if r.err || n < 0 || r.pos+n > len(r.buf) {
		r.err = true
		return nil
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b
}

// Rest returns all remaining unread bytes.
func (r *Reader) Rest() []byte {
	if r.err {
		return nil
	}
	b := r.buf[r.pos:]
	r.pos = len(r.buf)
	return b
}

// Xor writes a[i] ^ b[i] into dst for i in [0, n) where n is the minimum of the
// three slice lengths. dst may alias a or b.
func Xor(dst, a, b []byte) int {
	n := min(len(a), len(b), len(dst))
	for i := range n {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// MakeTokens returns a buffered channel pre-filled with n permits, used as a
// counting semaphore for flow-control windows (one permit per cell of credit).
func MakeTokens(n int) chan struct{} {
	ch := make(chan struct{}, n)
	for range n {
		ch <- struct{}{}
	}
	return ch
}
