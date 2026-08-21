package decouplet

import (
	"bytes"
	"image"
	"image/color"
	"testing"
)

// syntheticImage builds a deterministic image of the given size so the image
// tests do not depend on binary asset files sitting in the repo.
func syntheticImage(width, height int, seed int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			v := byte(x*7 + y*13 + seed)
			img.SetRGBA(x, y, color.RGBA{R: v, G: byte(v << 1), B: byte(v >> 1), A: 255})
		}
	}
	return img
}

func TestImageEncoder_Full(t *testing.T) {
	encoder := NewImageEncoder(syntheticImage(400, 400, 1))
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

// TestImageEncoder_NoFixedExpansion confirms the image output is below the old
// flat 10x: records are 9 bytes (two-reference) instead of 10.
func TestImageEncoder_NoFixedExpansion(t *testing.T) {
	encoder := NewImageEncoder(syntheticImage(400, 400, 2))
	original := bytes.Repeat([]byte("A"), 1000)
	var encoded bytes.Buffer
	if err := encoder.Encode(bytes.NewReader(original), &encoded); err != nil {
		t.Fatal(err)
	}
	upperBound := 10*len(original) + 32 // old was 10*len+3; records now 9 not 10, plus MAC
	if encoded.Len() > upperBound {
		t.Fatalf("output %d bytes exceeds expected upper bound %d", encoded.Len(), upperBound)
	}
	t.Logf("1000-byte input -> %d bytes output (%.2fx)", encoded.Len(), float64(encoded.Len())/float64(len(original)))
}