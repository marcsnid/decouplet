package decouplet

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"testing"
)

// This file holds the integrity-property tests for the v4 format (records
// + end checksum, no encryption). They make the claims testable: the key is
// required to authenticate, tampering is detected, the same byte has many
// different representations, sparse keys are rejected, and the format
// round-trips under fuzzing.

// TestByteEncoder_WrongKeyFails confirms a different key cannot authenticate
// the stream. The wrong key produces both wrong deltas (garbage bytes) and a
// wrong MAC, so the decoder rejects with ErrorTamper rather than returning
// garbage. Note: without encryption the deltas alone would not catch a wrong
// key; the MAC is what does.
func TestByteEncoder_WrongKeyFails(t *testing.T) {
	original := []byte("the quick brown fox jumps over the lazy dog")
	var enc bytes.Buffer
	if err := NewByteEncoder(makeRandKey(256)).Encode(bytes.NewReader(original), &enc); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	err := NewByteEncoder(makeRandKey(256)).Decode(bytes.NewReader(enc.Bytes()), &dec)
	if err == nil {
		t.Fatalf("wrong key decoded successfully; expected authentication failure")
	}
	if err != ErrorTamper {
		t.Fatalf("expected ErrorTamper, got %v", err)
	}
}

// TestImageEncoder_WrongKeyFails is the same check for the image encoder.
func TestImageEncoder_WrongKeyFails(t *testing.T) {
	original := []byte("secret image payload")
	var enc bytes.Buffer
	if err := NewImageEncoder(syntheticImage(400, 400, 1)).Encode(bytes.NewReader(original), &enc); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	err := NewImageEncoder(syntheticImage(400, 400, 99)).Decode(bytes.NewReader(enc.Bytes()), &dec)
	if err == nil {
		t.Fatalf("wrong key decoded successfully; expected authentication failure")
	}
	if err != ErrorTamper {
		t.Fatalf("expected ErrorTamper, got %v", err)
	}
}

// TestByteEncoder_TamperDetected confirms that flipping a single byte in the
// encoded records is caught by the MAC, instead of silently producing a
// modified message.
func TestByteEncoder_TamperDetected(t *testing.T) {
	original := []byte("transfer $1000 to bob")
	var enc bytes.Buffer
	key := makeRandKey(256)
	if err := NewByteEncoder(key).Encode(bytes.NewReader(original), &enc); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), enc.Bytes()...)
	// Flip a byte in the first record's coordinate data (position 3), which
	// changes the measured delta and therefore the recovered byte stream, and
	// also breaks the MAC.
	tampered[3] ^= 0x01
	var dec bytes.Buffer
	err := NewByteEncoder(key).Decode(bytes.NewReader(tampered), &dec)
	if err == nil {
		t.Fatalf("tampered message decoded successfully; expected an error")
	}
	if err != ErrorTamper {
		t.Fatalf("expected ErrorTamper, got %v", err)
	}
}

// TestByteEncoder_TagTamperDetected flips a tag byte, which the decoder's
// strict tag check rejects before even reaching the MAC, as a cheap early
// failure for framing corruption.
func TestByteEncoder_TagTamperDetected(t *testing.T) {
	original := []byte("some payload")
	var enc bytes.Buffer
	key := makeRandKey(256)
	if err := NewByteEncoder(key).Encode(bytes.NewReader(original), &enc); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), enc.Bytes()...)
	// Position 2 is the first tag byte. Flip it to an invalid value (0x01).
	tampered[2] = 0x01
	var dec bytes.Buffer
	err := NewByteEncoder(key).Decode(bytes.NewReader(tampered), &dec)
	if err == nil {
		t.Fatalf("tampered tag decoded successfully; expected an error")
	}
	if err != ErrorTruncated {
		t.Fatalf("expected ErrorTruncated for bad tag, got %v", err)
	}
}

// TestByteEncoder_Probabilistic confirms the same plaintext under the same key
// transcodes to different records every time, because of the random index
// draws. (There is no AEAD nonce anymore, but the random index draws still
// make the output differ.)
func TestByteEncoder_Probabilistic(t *testing.T) {
	enc := NewByteEncoder(makeRandKey(256))
	original := []byte("same message transcodes differently each time")
	var c1, c2 bytes.Buffer
	if err := enc.Encode(bytes.NewReader(original), &c1); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(bytes.NewReader(original), &c2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1.Bytes(), c2.Bytes()) {
		t.Fatalf("two transcodes of the same message produced identical output")
	}
}

// TestByteEncoder_HomophonicProperty tests that the same input byte is
// represented by many different records.
func TestByteEncoder_HomophonicProperty(t *testing.T) {
	key := makeRandKey(256)
	tc, err := buildByteTranscoder(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := bytes.Repeat([]byte{0x41}, 2000) // 'A' repeated
	var out bytes.Buffer
	if err := tc.transcode(stream, &out); err != nil {
		t.Fatal(err)
	}
	recs := out.Bytes()
	// Records are 3 bytes (two-reference, 1-byte indices). Count distinct ones.
	seen := make(map[[3]byte]bool)
	for i := 0; i+3 <= len(recs); i += 3 {
		var r [3]byte
		copy(r[:], recs[i:i+3])
		seen[r] = true
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct records for 2000 identical bytes", len(seen))
	}
	t.Logf("2000 identical bytes -> %d distinct records", len(seen))
	// Round-trip the stream. transcode does not write the end marker itself
	// (the pipeline adds header, end, and MAC around it), so append them here.
	var full bytes.Buffer
	full.Write(recs)
	full.WriteByte(endByte)
	back, err := tc.untranscode(bufio.NewReader(bytes.NewReader(full.Bytes())), &bufWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream, back) {
		t.Fatalf("transcode did not round-trip")
	}
}

// TestByteEncoder_KeyTooSparse confirms that a degenerate key that cannot
// represent all 256 bytes is rejected at validation, rather than failing
// silently during encoding.
func TestByteEncoder_KeyTooSparse(t *testing.T) {
	// A key of all zeros: every delta is 0, so only byte 0 is representable.
	key := make([]byte, 64)
	enc := NewByteEncoder(key)
	err := enc.Validate()
	if err != ErrorKeyTooSparse {
		t.Fatalf("expected ErrorKeyTooSparse for all-zero key, got %v", err)
	}
}

// TestByteEncoder_RoundTripFuzz hammers the round trip with random key sizes,
// message sizes, and content.
func TestByteEncoder_RoundTripFuzz(t *testing.T) {
	rng := newRNGFromSeed([32]byte{7, 7, 7})
	for iter := 0; iter < 200; iter++ {
		keyLen := 32 + rng.IntN(481) // 32..512 inclusive of max
		key := make([]byte, keyLen)
		crand.Read(key)

		msgLen := rng.IntN(4096)
		msg := make([]byte, msgLen)
		crand.Read(msg)

		enc := NewByteEncoder(key)
		var c bytes.Buffer
		if err := enc.Encode(bytes.NewReader(msg), &c); err != nil {
			t.Fatalf("iter %d: encode: %v (keyLen=%d)", iter, err, keyLen)
		}
		var d bytes.Buffer
		if err := enc.Decode(bytes.NewReader(c.Bytes()), &d); err != nil {
			t.Fatalf("iter %d: decode: %v (keyLen=%d msgLen=%d)", iter, err, keyLen, msgLen)
		}
		if !bytes.Equal(msg, d.Bytes()) {
			t.Fatalf("iter %d: round trip mismatch (keyLen=%d msgLen=%d)", iter, keyLen, msgLen)
		}
	}
}

// TestImageEncoder_RoundTripFuzz does the same for the image encoder.
func TestImageEncoder_RoundTripFuzz(t *testing.T) {
	rng := newRNGFromSeed([32]byte{9, 9, 9})
	for iter := 0; iter < 50; iter++ {
		size := 300 + rng.IntN(64)
		enc := NewImageEncoder(syntheticImage(size, size, iter))

		msgLen := rng.IntN(2048)
		msg := make([]byte, msgLen)
		crand.Read(msg)

		var c bytes.Buffer
		if err := enc.Encode(bytes.NewReader(msg), &c); err != nil {
			t.Fatalf("iter %d: encode: %v", iter, err)
		}
		var d bytes.Buffer
		if err := enc.Decode(bytes.NewReader(c.Bytes()), &d); err != nil {
			t.Fatalf("iter %d: decode: %v", iter, err)
		}
		if !bytes.Equal(msg, d.Bytes()) {
			t.Fatalf("iter %d: round trip mismatch (size=%d msgLen=%d)", iter, size, msgLen)
		}
	}
}