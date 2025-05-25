package decouplet

import (
	"bytes"
	"image"
	"os"
	"testing"
)

// For these tests, ensure you have:
// - A test image named "test.png" in the current directory or a specified path.
// - A second test image named "test2.png" for the ECB test.
// - A PPM image named "Tux.ppm" for the ECB test.

// TestImageEncoder_Full tests the encoding and decoding functionality of the ImageEncoder
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

// TestImageEncoder_OutputSize tests the output size of the encoded data
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

// TestImageEncoder_ImageECB tests the encoding and decoding of an image using ECB mode
func TestImageEncoder_ImageECB(t *testing.T) {
	// Load the first key image
	imgFile1, err := os.Open("test.png")
	if err != nil {
		t.Fatalf("failed to open test image 1: %v", err)
	}
	defer imgFile1.Close()
	imgData1, _, err := image.Decode(imgFile1)
	if err != nil {
		t.Fatalf("failed to decode image 1: %v", err)
	}

	// Load the second key image
	imgFile2, err := os.Open("test2.png")
	if err != nil {
		t.Fatalf("failed to open test image 2: %v", err)
	}
	defer imgFile2.Close()
	imgData2, _, err := image.Decode(imgFile2)
	if err != nil {
		t.Fatalf("failed to decode image 2: %v", err)
	}

	// Load the PPM image to encode
	ppmFile, err := os.Open("Tux.ppm")
	if err != nil {
		t.Fatalf("failed to open PPM file: %v", err)
	}
	defer ppmFile.Close()
	var ppmData bytes.Buffer
	if _, err := ppmData.ReadFrom(ppmFile); err != nil {
		t.Fatalf("failed to read PPM file: %v", err)
	}

	// Encode with key 1
	encoder1 := NewImageEncoder(imgData1)
	var encoded1 bytes.Buffer
	if err := encoder1.Encode(bytes.NewReader(ppmData.Bytes()), &encoded1); err != nil {
		t.Fatalf("encode with key 1 failed: %v", err)
	}

	// Decode with key 2 (should not recover the original image)
	encoder2 := NewImageEncoder(imgData2)
	var decodedWithWrongKey bytes.Buffer
	if err := encoder2.Decode(&encoded1, &decodedWithWrongKey); err != nil {
		t.Fatalf("decode with key 2 failed: %v", err)
	}
	if err := os.WriteFile("Tux.ecb.wrongkey.ppm", decodedWithWrongKey.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write decoded image with wrong key: %v", err)
	}

	// Try to open the output as an image (should fail)
	wrongKeyFile, err := os.Open("Tux.ecb.wrongkey.ppm")
	if err != nil {
		t.Fatalf("failed to open output file for verification: %v", err)
	}
	defer wrongKeyFile.Close()
	_, _, err = image.Decode(wrongKeyFile)
	if err == nil {
		t.Errorf("decoding with the wrong key produced a valid image, which should not happen")
	}
}
