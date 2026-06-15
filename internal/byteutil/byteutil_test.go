package byteutil

import (
	"bytes"
	"testing"
)

func TestWriterReaderRoundTrip(t *testing.T) {
	t.Parallel()
	w := NewWriter(0)
	w.Byte(0xab).U16(0x1234).U32(0xdeadbeef).U64(0x0102030405060708).Write([]byte("tail"))

	r := NewReader(w.Bytes())
	if got := r.Byte(); got != 0xab {
		t.Errorf("Byte = %#x", got)
	}
	if got := r.U16(); got != 0x1234 {
		t.Errorf("U16 = %#x", got)
	}
	if got := r.U32(); got != 0xdeadbeef {
		t.Errorf("U32 = %#x", got)
	}
	if got := r.U64(); got != 0x0102030405060708 {
		t.Errorf("U64 = %#x", got)
	}
	if got := r.Rest(); !bytes.Equal(got, []byte("tail")) {
		t.Errorf("Rest = %q", got)
	}
	if r.Err() {
		t.Error("unexpected reader error")
	}
}

func TestReaderUnderflow(t *testing.T) {
	t.Parallel()
	r := NewReader([]byte{0x01})
	_ = r.U32() // not enough bytes
	if !r.Err() {
		t.Error("expected underflow error")
	}
	if got := r.Bytes(4); got != nil {
		t.Errorf("Bytes after error = %v, want nil", got)
	}
}

func TestXor(t *testing.T) {
	t.Parallel()
	a := []byte{0xff, 0x0f, 0xaa}
	b := []byte{0x0f, 0xff, 0x55}
	dst := make([]byte, 3)
	n := Xor(dst, a, b)
	if n != 3 {
		t.Fatalf("n = %d", n)
	}
	want := []byte{0xf0, 0xf0, 0xff}
	if !bytes.Equal(dst, want) {
		t.Errorf("Xor = %x, want %x", dst, want)
	}
}
