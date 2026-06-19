package directory

import (
	"bytes"
	"compress/zlib"
	"testing"
)

// TestReadLimitedRejectsOversized covers the decompression-bomb guard: a stream
// larger than the limit is rejected, while one at the limit is accepted.
func TestReadLimitedRejectsOversized(t *testing.T) {
	t.Parallel()
	if _, err := readLimited(bytes.NewReader(make([]byte, 100)), 50); err == nil {
		t.Fatal("readLimited accepted a stream over the limit")
	}
	got, err := readLimited(bytes.NewReader(make([]byte, 50)), 50)
	if err != nil || len(got) != 50 {
		t.Fatalf("readLimited at the limit: len=%d err=%v", len(got), err)
	}
}

// TestDecompressDeflateRoundTrip exercises the zlib "deflate" decode path the
// directory client uses for authority/HSDir responses.
func TestDecompressDeflateRoundTrip(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("tor directory document\n"), 1000)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(want); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	got, err := Decompress("deflate", buf.Bytes())
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("deflate round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}
