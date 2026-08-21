package decouplet

import (
	"bytes"
	crand "crypto/rand"
	"testing"
)

func makeRandKey(n int) []byte {
	k := make([]byte, n)
	crand.Read(k)
	return k
}

func TestByteEncoder_Full(t *testing.T) {
	encoder := NewByteEncoder(makeRandKey(256))
	original := []byte("Hello, decouplet byte encoding!")
	var encoded bytes.Buffer
	if err := encoder.Encode(bytes.NewReader(original), &encoded); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	var decoded bytes.Buffer
	if err := encoder.Decode(&encoded, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(original, decoded.Bytes()) {
		t.Errorf("decoded output does not match original.\nOriginal: %q\nDecoded: %q", original, decoded.Bytes())
	}
}

// TestByteEncoder_Header confirms the leading bytes are STX + version 0x04 and
// the stream ends with the 16-byte MAC tag.
func TestByteEncoder_Header(t *testing.T) {
	var encoded bytes.Buffer
	if err := NewByteEncoder(makeRandKey(64)).Encode(bytes.NewReader([]byte("x")), &encoded); err != nil {
		t.Fatal(err)
	}
	b := encoded.Bytes()
	if b[0] != 0x02 || b[1] != 0x04 {
		t.Fatalf("expected STX+version 0x02 0x04, got % x", b[:2])
	}
	// The byte before the 16-byte MAC tag is the end marker 0xFF.
	if b[len(b)-macSize-1] != 0xFF {
		t.Fatalf("expected end marker 0xFF before the MAC, got % x", b[len(b)-macSize-1])
	}
}

// TestByteEncoder_NoFixedExpansion confirms the output is no longer a flat 5x:
// with a 256-byte key the per-record size is 3 bytes (two-reference), so total
// expansion is well below the old 5x.
func TestByteEncoder_NoFixedExpansion(t *testing.T) {
	encoder := NewByteEncoder(makeRandKey(256))
	original := bytes.Repeat([]byte("A"), 1000)
	var encoded bytes.Buffer
	if err := encoder.Encode(bytes.NewReader(original), &encoded); err != nil {
		t.Fatal(err)
	}
	// Records are mostly 3 bytes (two-reference, 1-byte indices), plus header
	// (2), end marker (1), and MAC (16). So output is roughly 3*len + 19.
	upperBound := 4*len(original) + 32 // generous; old was 5*len+3
	if encoded.Len() > upperBound {
		t.Fatalf("output %d bytes exceeds expected upper bound %d (old design was 5x)", encoded.Len(), upperBound)
	}
	t.Logf("1000-byte input -> %d bytes output (%.2fx)", encoded.Len(), float64(encoded.Len())/float64(len(original)))
}