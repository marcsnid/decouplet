package decouplet

import (
	"bufio"
	"hash"
	"io"
)

const (
	byteMaxKeySize = 512 // Maximum key size for byte encoder
	byteMinKeySize = 32  // Minimum key size for byte encoder

	// Cap the number of index pairs stored per delta so the precompute table
	// stays bounded.
	bytePairsPerDeltaCap = 4096
)

// ByteEncoder encodes a byte stream using a byte slice as the key.
//
// Each byte is represented as the difference between two key positions,
// key[a] - key[b], with a three-position fallback key[a] - key[b] + key[c]
// when no two-position pair exists for that byte.
type byteEncoder struct {
	Key []byte
	tc  *byteTranscoder
}

func NewByteEncoder(key []byte) Encoder {
	return &byteEncoder{Key: key}
}

func (b *byteEncoder) Encode(r io.Reader, w io.Writer) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return encodeStream(b.tc, b.Key, r, w)
}

func (b *byteEncoder) Decode(r io.Reader, w io.Writer) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return decodeStream(b.tc, b.Key, r, w)
}

func (b *byteEncoder) Validate() error {
	if len(b.Key) == 0 {
		return ErrorInvalidKey
	}
	if len(b.Key) < byteMinKeySize || len(b.Key) > byteMaxKeySize {
		return ErrorBytesInvalidKeyLength
	}
	if b.tc == nil {
		tc, err := buildByteTranscoder(b.Key)
		if err != nil {
			return err
		}
		b.tc = tc
	}
	return nil
}

// byteTranscoder holds the precomputed tables for one byte key.
type byteTranscoder struct {
	key      []byte
	idxWidth int
	// deltaPairs[d] is a list of (a, b) index pairs with key[a]-key[b] == d.
	// Capped at bytePairsPerDeltaCap entries to bound memory.
	deltaPairs [256][][2]uint16
	// representable[b] is true if byte b can be carried by a two- or
	// three-position relation into this key.
	representable [256]bool
}

func buildByteTranscoder(key []byte) (*byteTranscoder, error) {
	n := len(key)
	tc := &byteTranscoder{key: key, idxWidth: indexWidth(n)}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			d := uint8(int(key[i]) - int(key[j]))
			if len(tc.deltaPairs[d]) < bytePairsPerDeltaCap {
				tc.deltaPairs[d] = append(tc.deltaPairs[d], [2]uint16{uint16(i), uint16(j)})
			}
		}
	}
	// A byte is representable if a two-position pair exists, or a three-position
	// pair exists: key[a]-key[b]+key[c] == b, i.e. key[a]-key[b] == b-key[c].
	for b := 0; b < 256; b++ {
		if len(tc.deltaPairs[uint8(b)]) > 0 {
			tc.representable[b] = true
			continue
		}
		for x3 := 0; x3 < n; x3++ {
			need := uint8(int(b) - int(key[x3]))
			if len(tc.deltaPairs[need]) > 0 {
				tc.representable[b] = true
				break
			}
		}
	}
	for b := 0; b < 256; b++ {
		if !tc.representable[b] {
			return nil, ErrorKeyTooSparse
		}
	}
	return tc, nil
}

func (b *byteEncoder) transcodeChunk(chunk []byte, w io.Writer, rng *fastRNG) error {
	return b.tc.transcodeChunk(chunk, w, rng)
}

func (b *byteEncoder) untranscode(r *bufio.Reader, w io.Writer, h hash.Hash) error {
	return b.tc.untranscode(r, w, h)
}

func (tc *byteTranscoder) transcodeChunk(chunk []byte, w io.Writer, rng *fastRNG) error {
	width := tc.idxWidth
	n := len(tc.key)
	var rec [7]byte // tag + up to 3 two-byte indices
	for _, byt := range chunk {
		pairs := tc.deltaPairs[byt]
		if len(pairs) > 0 {
			p := pairs[rng.IntN(len(pairs))]
			rec[0] = 0x00 // two-reference tag
			putIdx(rec[1:], width, int(p[0]))
			putIdx(rec[1+width:], width, int(p[1]))
			if _, err := w.Write(rec[:1+2*width]); err != nil {
				return err
			}
			continue
		}
		// Three-reference fallback: find x3 so that key[a]-key[b] == byt-key[x3]
		// is a reachable two-reference delta.
		var x3 int
		found := false
		for x := 0; x < n; x++ {
			need := uint8(int(byt) - int(tc.key[x]))
			if len(tc.deltaPairs[need]) > 0 {
				x3 = x
				found = true
				break
			}
		}
		if !found {
			return ErrorKeyTooSparse
		}
		need := uint8(int(byt) - int(tc.key[x3]))
		p := tc.deltaPairs[need][rng.IntN(len(tc.deltaPairs[need]))]
		rec[0] = 0x80 // three-reference tag
		putIdx(rec[1:], width, int(p[0]))
		putIdx(rec[1+width:], width, int(p[1]))
		putIdx(rec[1+2*width:], width, x3)
		if _, err := w.Write(rec[:1+3*width]); err != nil {
			return err
		}
	}
	return nil
}

func (tc *byteTranscoder) untranscode(r *bufio.Reader, w io.Writer, h hash.Hash) error {
	br := r
	width := tc.idxWidth
	n := len(tc.key)
	var rec [7]byte  // tag + up to 3 two-byte indices
	var one [1]byte
	for {
		tag, err := br.ReadByte()
		if err == io.EOF {
			return ErrorTruncated // a well-formed stream ends with endByte
		}
		if err != nil {
			return err
		}
		if tag == endByte {
			break
		}
		// The byte encoder only ever writes 0x00 (two-reference) or 0x80
		// (three-reference). Any other value means the stream is corrupted.
		if tag != 0x00 && tag != 0x80 {
			return ErrorTruncated
		}
		three := tag&0x80 != 0
		// Collect the whole record into rec so we can feed it to the MAC in one
		// Write instead of one per byte.
		rec[0] = tag
		off := 1
		x1, off2, err := readIdxInto(br, width, rec[:], off)
		if err != nil {
			return ErrorTruncated
		}
		off = off2
		x2, off2, err := readIdxInto(br, width, rec[:], off)
		if err != nil {
			return ErrorTruncated
		}
		off = off2
		if x1 >= n || x2 >= n {
			return ErrorTruncated
		}
		v := int(tc.key[x1]) - int(tc.key[x2])
		if three {
			x3, off2, err := readIdxInto(br, width, rec[:], off)
			if err != nil {
				return ErrorTruncated
			}
			off = off2
			if x3 >= n {
				return ErrorTruncated
			}
			v += int(tc.key[x3])
		}
		h.Write(rec[:off])
		one[0] = byte((v%256 + 256) % 256)
		if _, err := w.Write(one[:]); err != nil {
			return err
		}
	}
	return nil
}

// readIdxInto reads a 1- or 2-byte index from a buffered reader into buf at the
// given offset, returning the index value, the new offset, and any error.
func readIdxInto(br *bufio.Reader, width int, buf []byte, off int) (int, int, error) {
	if width == 1 {
		b, err := br.ReadByte()
		if err != nil {
			return 0, off, err
		}
		buf[off] = b
		return int(b), off + 1, nil
	}
	hi, err := br.ReadByte()
		if err != nil {
			return 0, off, err
		}
	lo, err := br.ReadByte()
	if err != nil {
		return 0, off, err
	}
	buf[off] = hi
	buf[off+1] = lo
	return int(hi)<<8 | int(lo), off + 2, nil
}