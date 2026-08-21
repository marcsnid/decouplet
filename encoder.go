package decouplet

import (
	"bufio"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"math/rand/v2"
)

// Package decouplet transforms input bytes into records that reference
// positions in a shared key, so the output does not resemble the input.
// A keyed checksum is included so the decoder can detect tampering and
// reject the wrong key.
//
// Decouplet is not encryption. Anyone with the key can read the bytes back.
// For secrecy, encrypt the data with your own cipher first, then encode it.

var (
	ErrorInvalidKey            = errors.New("invalid key")
	ErrorBytesInvalidKeyLength = errors.New("invalid key length, must be between 32 and 512 bytes")
	ErrorImageKeyTooSmall      = errors.New("key needs to be larger than 300x300")
	ErrorUnknownVersion        = errors.New("unknown decouplet version")
	ErrorKeyTooSparse          = errors.New("key cannot represent all 256 byte values, use a richer key")
	ErrorTamper                = errors.New("authentication failed: wrong key or tampered data")
	ErrorTruncated             = errors.New("truncated record or missing end marker")
)

const (
	stxByte   byte = 0x02 // Start marker, read once at the head of the stream.
	versionV4 byte = 0x04 // Wire format version.
	endByte   byte = 0xFF // End marker, scanned at each record boundary.

	// 0xFF is used instead of the classic ETX (0x03) because 0x03 is a valid
	// image record tag (channel A, two references). 0xFF is never a valid tag
	// for either encoder, so it is an unambiguous end marker.

	macSize = 16 // truncated HMAC-SHA256 tag, written once at the end of the stream
)

type Encoder interface {
	Encode(io.Reader, io.Writer) error
	Decode(io.Reader, io.Writer) error
	Validate() error
}

// writeHeader writes the start marker and version byte.
func writeHeader(w io.Writer) error {
	_, err := w.Write([]byte{stxByte, versionV4})
	return err
}

// readHeader reads and verifies the start marker and version byte, refusing
// data encoded with a version this decoder does not understand.
func readHeader(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if header[0] != stxByte {
		return ErrorTruncated
	}
	if header[1] != versionV4 {
		return ErrorUnknownVersion
	}
	return nil
}

// macKey derives the MAC key from the user key with a domain separator, so the
// MAC key and the key lookup table are distinct even though they come from the
// same input.
func macKey(key []byte) []byte {
	h := sha256.New()
	h.Write([]byte("decouplet-mac-v1"))
	h.Write(key)
	return h.Sum(nil)
}

// macFor returns the truncated HMAC-SHA256 tag over the given record bytes.
func macFor(key, records []byte) []byte {
	m := hmac.New(sha256.New, macKey(key))
	m.Write(records)
	sum := m.Sum(nil)
	return sum[:macSize]
}

// encodeStream runs the full encode pipeline: write the header, transcode the
// plaintext into records, then write the end marker and a MAC over the records.
func encodeStream(e transcoder, key []byte, r io.Reader, w io.Writer) error {
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	var recs bufWriter
	if err := writeHeader(w); err != nil {
		return err
	}
	if err := e.transcode(plaintext, &recs); err != nil {
		return err
	}
	if _, err := w.Write(recs.b); err != nil {
		return err
	}
	if err := writeEnd(w); err != nil {
		return err
	}
	tag := macFor(key, recs.b)
	_, err = w.Write(tag)
	return err
}

// decodeStream runs the full decode pipeline: read the header, read records
// into a byte stream, then verify the MAC before returning the bytes.
func decodeStream(e transcoder, key []byte, r io.Reader, w io.Writer) error {
	if err := readHeader(r); err != nil {
		return err
	}
	br := bufio.NewReader(r)
	var recs bufWriter
	recs.b = make([]byte, 0, 4096)
	stream, err := e.untranscode(br, &recs)
	if err != nil {
		return err
	}
	tag := make([]byte, macSize)
	if _, err := io.ReadFull(br, tag); err != nil {
		return ErrorTruncated
	}
	want := macFor(key, recs.b)
	if !hmac.Equal(tag, want) {
		return ErrorTamper
	}
	_, err = w.Write(stream)
	return err
}

// writeEnd writes the end marker that terminates the record stream.
func writeEnd(w io.Writer) error {
	_, err := w.Write([]byte{endByte})
	return err
}

// transcoder is the encoder-specific layer. transcode turns a byte stream
// into records; untranscode reverses it by measuring the deltas and also
// returns the raw record bytes so the caller can checksum them.
type transcoder interface {
	transcode(stream []byte, w io.Writer) error
	untranscode(r *bufio.Reader, recs *bufWriter) ([]byte, error)
}

// bufWriter is a thin wrapper around a byte slice so the transcoders can append
// records without per-write allocations.
type bufWriter struct {
	b []byte
}

func (bw *bufWriter) Write(p []byte) (int, error) {
	bw.b = append(bw.b, p...)
	return len(p), nil
}

// fastRNG wraps a ChaCha8 CSPRNG seeded once from crypto/rand so that index
// draws are cryptographically random without a syscall and a math/big
// allocation on every draw.
type fastRNG struct {
	c *rand.ChaCha8
}

func newRNG() (*fastRNG, error) {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return nil, err
	}
	return &fastRNG{c: rand.NewChaCha8(seed)}, nil
}

func newRNGFromSeed(seed [32]byte) *fastRNG {
	return &fastRNG{c: rand.NewChaCha8(seed)}
}

// IntN returns a non-negative random int below n. The indices are public
// (recorded in the ciphertext) and carry no security by themselves, so a plain
// modulo is fine; the integrity lives in the MAC.
func (g *fastRNG) IntN(n int) int {
	if n <= 0 {
		return 0
	}
	return int(g.c.Uint64() % uint64(n))
}

// indexWidth returns 1 when the key fits in a byte, otherwise 2. Both encoder
// and decoder derive this from the key they hold, so the width does not need to
// be transmitted.
func indexWidth(keyLen int) int {
	if keyLen <= 256 {
		return 1
	}
	return 2
}

func putIdx(buf []byte, width, idx int) {
	if width == 1 {
		buf[0] = byte(idx)
		return
	}
	buf[0] = byte(idx >> 8)
	buf[1] = byte(idx)
}