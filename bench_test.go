package decouplet

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"image"
	"image/color"
	"io"
	"math/big"
	"testing"
)

// This file re-implements the old byte encoder purely for benchmark comparison,
// so we can measure the current version against the scheme that shipped for
// years. These are NOT used by the library; they live only in tests.

func legacyOriginalEncode(key, data []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte(0x02)
	for _, b := range data {
		x1, err := crand.Int(crand.Reader, big.NewInt(int64(len(key))))
		if err != nil {
			return nil, err
		}
		x2, err := crand.Int(crand.Reader, big.NewInt(int64(len(key))))
		if err != nil {
			return nil, err
		}
		supplement := byte(0)
		for s := 0; s < 256; s++ {
			if b == byte((int(x1.Int64())-int(x2.Int64())+s+256)%256) {
				supplement = uint8(s)
				break
			}
		}
		binary.Write(&out, binary.BigEndian, uint16(x1.Int64()))
		binary.Write(&out, binary.BigEndian, uint16(x2.Int64()))
		out.WriteByte(supplement)
	}
	out.WriteByte(0x03)
	return out.Bytes(), nil
}

func benchImageKey(n int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			img.SetRGBA(x, y, color.RGBA{R: byte(x), G: byte(y), B: byte(x ^ y), A: 255})
		}
	}
	return img
}

// --- byte benchmarks ---

func benchByteEncode(b *testing.B, n int) {
	enc := NewByteEncoder(makeRandKey(256))
	data := bytes.Repeat([]byte{0xAB}, n)
	b.ReportAllocs()
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := enc.Encode(bytes.NewReader(data), &out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkByteEncode_1KB(b *testing.B)  { benchByteEncode(b, 1 << 10) }
func BenchmarkByteEncode_16KB(b *testing.B) { benchByteEncode(b, 1 << 14) }
func BenchmarkByteEncode_64KB(b *testing.B) { benchByteEncode(b, 1 << 16) }

func BenchmarkByteDecode_16KB(b *testing.B) {
	enc := NewByteEncoder(makeRandKey(256))
	data := bytes.Repeat([]byte{0xAB}, 1<<14)
	var encoded bytes.Buffer
	if err := enc.Encode(bytes.NewReader(data), &encoded); err != nil {
		b.Fatal(err)
	}
	encBytes := encoded.Bytes()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := enc.Decode(bytes.NewReader(encBytes), &out); err != nil {
			b.Fatal(err)
		}
	}
}

// --- image benchmarks ---

func BenchmarkImageEncode_16KB(b *testing.B) {
	enc := NewImageEncoder(benchImageKey(320))
	data := bytes.Repeat([]byte{0xAB}, 1<<14)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := enc.Encode(bytes.NewReader(data), &out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkImageDecode_16KB(b *testing.B) {
	enc := NewImageEncoder(benchImageKey(320))
	data := bytes.Repeat([]byte{0xAB}, 1<<14)
	var encoded bytes.Buffer
	if err := enc.Encode(bytes.NewReader(data), &encoded); err != nil {
		b.Fatal(err)
	}
	encBytes := encoded.Bytes()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := enc.Decode(bytes.NewReader(encBytes), &out); err != nil {
			b.Fatal(err)
		}
	}
}

// --- legacy comparison ---

func BenchmarkByteEncode_LegacyOriginal_256B(b *testing.B) {
	key := makeRandKey(256)
	data := bytes.Repeat([]byte{0xAB}, 256)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := legacyOriginalEncode(key, data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkByteEncode_LegacyOriginal_1KB(b *testing.B) {
	key := makeRandKey(256)
	data := bytes.Repeat([]byte{0xAB}, 1<<10)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := legacyOriginalEncode(key, data); err != nil {
			b.Fatal(err)
		}
	}
}

// TestStreaming_PipeRoundTrip proves encode and decode actually stream: it pipes
// a large input through an io.Pipe, so if Encode buffered the whole input before
// writing any output, the pipe would deadlock (the pipe buffer is small). This
// would hang or fail with a timeout, not pass.
func TestStreaming_PipeRoundTrip(t *testing.T) {
	key := makeRandKey(256)
	enc := NewByteEncoder(key)

	size := 1 << 20 // 1 MB
	data := make([]byte, size)
	crand.Read(data)

	// Encode: read from src pipe, write to a bytes.Buffer.
	pr, pw := io.Pipe()
	var encoded bytes.Buffer
	encodeErr := make(chan error, 1)
	go func() {
		encodeErr <- enc.Encode(pr, &encoded)
	}()

	// Feed the data in slowly. If Encode is buffering, this goroutine fills the
	// pipe's buffer (64KB) and then blocks until Encode drains it, which only
	// happens if Encode is reading and writing concurrently.
	go func() {
		chunk := make([]byte, 4096)
		for i := 0; i < size; {
			n := copy(chunk, data[i:])
			pw.Write(chunk[:n])
			i += n
		}
		pw.Close()
	}()

	if err := <-encodeErr; err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Decode back.
	var decoded bytes.Buffer
	if err := enc.Decode(bytes.NewReader(encoded.Bytes()), &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(data, decoded.Bytes()) {
		t.Fatalf("round trip mismatch on %d bytes", size)
	}
	t.Logf("streamed %d bytes through a pipe and round-tripped OK", size)
}