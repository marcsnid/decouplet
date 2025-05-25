package decouplet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestByteEncoder_Full tests the encoding and decoding functionality of the ByteEncoder
func TestByteEncoder_Full(t *testing.T) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	encoder := NewByteEncoder(key)

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

// TestByteEncoder_OutputSize tests the output size of the encoded data
func TestByteEncoder_OutputSize(t *testing.T) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	encoder := NewByteEncoder(key)
	original := []byte("This is a test message to check encoded output size.")
	var encoded bytes.Buffer

	if err := encoder.Encode(bytes.NewReader(original), &encoded); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	expected := len(original)*5 + 2 // Each byte can expand to 5 bytes + 2 for STX and ETX
	if encoded.Len() != expected {
		t.Errorf("Encoded output size mismatch. Expected: %d, Got: %d", expected, encoded.Len())
	}
}
