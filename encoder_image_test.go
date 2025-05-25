package decouplet

import (
	"bytes"
	"image"
	"os"
	"testing"
)

func TestImageEncoder_Full(t *testing.T) {
	// Load a test image (ensure test.png exists in your testdata or images directory)
	imgFile, err := os.Open("test.png")
	if err != nil {
		t.Fatalf("failed to open test image: %v", err)
	}
	defer imgFile.Close()

	imgData, _, err := image.Decode(imgFile)
	if err != nil {
		t.Fatalf("failed to decode image: %v", err)
	}

	encoder := NewImageEncoder(imgData)

	original := []byte("Hello, decouplet image encoding!")
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

func TestImageEncoder_OutputSize(t *testing.T) {
	imgFile, err := os.Open("test.png")
	if err != nil {
		t.Fatalf("failed to open test image: %v", err)
	}
	defer imgFile.Close()

	imgData, _, err := image.Decode(imgFile)
	if err != nil {
		t.Fatalf("failed to decode image: %v", err)
	}

	encoder := NewImageEncoder(imgData)
	original := []byte("This is a test message to check encoded output size.")
	var encoded bytes.Buffer

	if err := encoder.Encode(bytes.NewReader(original), &encoded); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	expected := len(original)*10 + 2 // Each byte expands to 10 bytes + 2 for STX and ETX
	if encoded.Len() != expected {
		t.Errorf("Encoded output size mismatch. Expected: %d, Got: %d", expected, encoded.Len())
	}
}
