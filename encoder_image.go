package decouplet

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"image"
	"io"
)

const (
	imageChannelR uint8 = iota
	imageChannelG
	imageChannelB
	imageChannelA
	imageChannelC
	imageChannelM
	imageChannelY
	imageChannelK

	imageKeySize = 300 // minimum image dimension

	// Cap coords stored per (channel, value) to bound memory for large images.
	imageCoordsPerValueCap = 256
)

// ImageEncoder encodes a byte stream using an image as the key.
//
// Each byte is represented as the difference between two pixel values in a
// chosen channel, pixel(p1) - pixel(p2), with a three-pixel fallback
// pixel(p1) - pixel(p2) + pixel(p3) when no two-pixel pair exists. The channel
// and the two-or-three flag are carried by the record tag byte.
type imageEncoder struct {
	Key image.Image
	tc  *imageTranscoder
}

func NewImageEncoder(key image.Image) Encoder {
	return &imageEncoder{Key: key}
}

func (i *imageEncoder) Encode(r io.Reader, w io.Writer) error {
	if err := i.Validate(); err != nil {
		return err
	}
	return encodeStream(i.tc, i.tc.macKey, r, w)
}

func (i *imageEncoder) Decode(r io.Reader, w io.Writer) error {
	if err := i.Validate(); err != nil {
		return err
	}
	return decodeStream(i.tc, i.tc.macKey, r, w)
}

func (i *imageEncoder) Validate() error {
	if i.Key == nil {
		return ErrorInvalidKey
	}
	if i.Key.Bounds().Max.X < imageKeySize || i.Key.Bounds().Max.Y < imageKeySize {
		return ErrorImageKeyTooSmall
	}
	if i.tc == nil {
		tc, err := buildImageTranscoder(i.Key)
		if err != nil {
			return err
		}
		i.tc = tc
	}
	return nil
}

// imgCoord is a pixel position stored in the ciphertext records.
type imgCoord struct {
	x, y uint16
}

// imageTranscoder holds the precomputed tables for one image key.
type imageTranscoder struct {
	img      image.Image
	width    int
	height   int
	channels []uint8
	macKey   []byte // MAC key derived from the image, cached once
	// valueCoords[ch][v] is a list of pixel coordinates whose value in channel
	// ch equals v. Capped per value to bound memory.
	valueCoords [8][256][]imgCoord
	// present[ch][v] is true if valueCoords[ch][v] is non-empty.
	present [8][256]bool
	// presentList[ch] is the list of values that occur in channel ch.
	presentList [8][]uint8
	// twoRefV2[ch][b] is the list of v2 values such that a pair of pixels with
	// values (v2+b, v2) in channel ch carries byte b.
	twoRefV2 [8][256][]uint8
	// representable[b] is true if byte b can be carried in some channel.
	representable [256]bool
}

func buildImageTranscoder(img image.Image) (*imageTranscoder, error) {
	bounds := img.Bounds()
	tc := &imageTranscoder{
		img:      img,
		width:    bounds.Dx(),
		height:   bounds.Dy(),
		channels: imageChannels(img),
	}
	for _, ch := range tc.channels {
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				v := pixelVal(img, x, y, ch)
				if len(tc.valueCoords[ch][v]) < imageCoordsPerValueCap {
					tc.valueCoords[ch][v] = append(tc.valueCoords[ch][v], imgCoord{uint16(x), uint16(y)})
				}
				if !tc.present[ch][v] {
					tc.present[ch][v] = true
					tc.presentList[ch] = append(tc.presentList[ch], v)
				}
			}
		}
	}
	// Build two-reference reachability per channel and per byte.
	for _, ch := range tc.channels {
		for b := 0; b < 256; b++ {
			for _, v2 := range tc.presentList[ch] {
				v1 := uint8(int(v2) + int(b))
				if tc.present[ch][v1] {
					tc.twoRefV2[ch][b] = append(tc.twoRefV2[ch][b], v2)
				}
			}
		}
	}
	// A byte is representable if some channel can carry it with two or three
	// references. Three references: pixel(p1)-pixel(p2)+pixel(p3) == b, i.e.
	// pixel(p1)-pixel(p2) == b-pixel(p3), so some v3 has twoRefV2[ch][b-v3].
	for b := 0; b < 256; b++ {
		for _, ch := range tc.channels {
			if len(tc.twoRefV2[ch][b]) > 0 {
				tc.representable[b] = true
				break
			}
			for _, v3 := range tc.presentList[ch] {
				need := uint8(int(b) - int(v3))
				if len(tc.twoRefV2[ch][need]) > 0 {
					tc.representable[b] = true
					break
				}
			}
			if tc.representable[b] {
				break
			}
		}
	}
	for b := 0; b < 256; b++ {
		if !tc.representable[b] {
			return nil, ErrorKeyTooSparse
		}
	}
	// Derive a stable MAC key from the image so a different image key fails
	// authentication. Dimensions are included so two differently sized images
	// cannot share a MAC key.
	h := sha256.New()
	var db [8]byte
	binary.BigEndian.PutUint32(db[0:4], uint32(bounds.Dx()))
	binary.BigEndian.PutUint32(db[4:8], uint32(bounds.Dy()))
	h.Write(db[:])
	for _, ch := range tc.channels {
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				h.Write([]byte{pixelVal(img, x, y, ch)})
			}
		}
	}
	tc.macKey = h.Sum(nil)
	return tc, nil
}

func (i *imageEncoder) transcode(stream []byte, w io.Writer) error {
	return i.tc.transcode(stream, w)
}

func (i *imageEncoder) untranscode(r *bufio.Reader, recs *bufWriter) ([]byte, error) {
	return i.tc.untranscode(r, recs)
}

func (tc *imageTranscoder) transcode(stream []byte, w io.Writer) error {
	rng, err := newRNG()
	if err != nil {
		return err
	}
	channels := tc.channels
	var orderBuf [8]int
	var rec [13]byte // tag + up to 3 two-byte coordinate pairs
	for _, byt := range stream {
		// Pick a channel that can carry this byte, trying channels in random
		// order. Two references are preferred over three.
		order := orderBuf[:len(channels)]
		rngChannelOrder(rng, order, len(channels))
		done := false
		for _, ci := range order {
			ch := channels[ci]
			if v2s := tc.twoRefV2[ch][byt]; len(v2s) > 0 {
				v2 := v2s[rng.IntN(len(v2s))]
				v1 := uint8(int(v2) + int(byt))
				c1 := tc.valueCoords[ch][v1][rng.IntN(len(tc.valueCoords[ch][v1]))]
				c2 := tc.valueCoords[ch][v2][rng.IntN(len(tc.valueCoords[ch][v2]))]
				rec[0] = ch // two-reference tag carries just the channel
				putImgCoord(rec[1:], c1)
				putImgCoord(rec[5:], c2)
				if _, err := w.Write(rec[:9]); err != nil {
					return err
				}
				done = true
				break
			}
		}
		if done {
			continue
		}
		// Three-reference fallback across channels.
		for _, ci := range order {
			ch := channels[ci]
			for _, v3 := range tc.presentList[ch] {
				need := uint8(int(byt) - int(v3))
				if len(tc.twoRefV2[ch][need]) > 0 {
					v2 := tc.twoRefV2[ch][need][rng.IntN(len(tc.twoRefV2[ch][need]))]
					v1 := uint8(int(v2) + int(need))
					c1 := tc.valueCoords[ch][v1][rng.IntN(len(tc.valueCoords[ch][v1]))]
					c2 := tc.valueCoords[ch][v2][rng.IntN(len(tc.valueCoords[ch][v2]))]
					c3 := tc.valueCoords[ch][v3][rng.IntN(len(tc.valueCoords[ch][v3]))]
					rec[0] = ch | 0x80 // three-reference tag
					putImgCoord(rec[1:], c1)
					putImgCoord(rec[5:], c2)
					putImgCoord(rec[9:], c3)
					if _, err := w.Write(rec[:13]); err != nil {
						return err
					}
					done = true
					break
				}
			}
			if done {
				break
			}
		}
		if !done {
			return ErrorKeyTooSparse
		}
	}
	return nil
}

func (tc *imageTranscoder) untranscode(r *bufio.Reader, recs *bufWriter) ([]byte, error) {
	br := r
	out := make([]byte, 0, 256)
	for {
		tag, err := br.ReadByte()
		if err == io.EOF {
			return nil, ErrorTruncated
		}
		if err != nil {
			return nil, err
		}
		if tag == endByte {
			break
		}
		ch := tag & 0x7F
		three := tag&0x80 != 0
		// Record the raw tag byte for the MAC.
		recs.b = append(recs.b, tag)
		c1, err := readImgCoordBR(br, recs)
		if err != nil {
			return nil, ErrorTruncated
		}
		c2, err := readImgCoordBR(br, recs)
		if err != nil {
			return nil, ErrorTruncated
		}
		if !tc.inBounds(c1) || !tc.inBounds(c2) {
			return nil, ErrorTruncated
		}
		v := int(pixelVal(tc.img, int(c1.x), int(c1.y), ch)) - int(pixelVal(tc.img, int(c2.x), int(c2.y), ch))
		if three {
			c3, err := readImgCoordBR(br, recs)
			if err != nil {
				return nil, ErrorTruncated
			}
			if !tc.inBounds(c3) {
				return nil, ErrorTruncated
			}
			v += int(pixelVal(tc.img, int(c3.x), int(c3.y), ch))
		}
		out = append(out, byte((v%256+256)%256))
	}
	return out, nil
}

func (tc *imageTranscoder) inBounds(c imgCoord) bool {
	b := tc.img.Bounds()
	return int(c.x) >= b.Min.X && int(c.x) < b.Max.X && int(c.y) >= b.Min.Y && int(c.y) < b.Max.Y
}

func putImgCoord(buf []byte, c imgCoord) {
	binary.BigEndian.PutUint16(buf[0:2], c.x)
	binary.BigEndian.PutUint16(buf[2:4], c.y)
}

// readImgCoordBR reads a 4-byte coordinate from a buffered reader without the
// per-call heap escape that io.ReadFull with a stack buffer would cause, and
// appends the raw bytes to recs so the MAC covers them.
func readImgCoordBR(br *bufio.Reader, recs *bufWriter) (imgCoord, error) {
	xHi, err := br.ReadByte()
	if err != nil {
		return imgCoord{}, err
	}
	xLo, err := br.ReadByte()
	if err != nil {
		return imgCoord{}, err
	}
	yHi, err := br.ReadByte()
	if err != nil {
		return imgCoord{}, err
	}
	yLo, err := br.ReadByte()
	if err != nil {
		return imgCoord{}, err
	}
	recs.b = append(recs.b, xHi, xLo, yHi, yLo)
	return imgCoord{uint16(xHi)<<8 | uint16(xLo), uint16(yHi)<<8 | uint16(yLo)}, nil
}

// pixelVal reads a single channel value from an image, handling RGBA and CMYK.
// For the common *image.RGBA case it reads the backing pixel buffer directly to
// avoid the heap allocation that img.At(x,y) causes by returning a color.Color
// interface.
func pixelVal(img image.Image, x, y int, ch uint8) uint8 {
	if rgba, ok := img.(*image.RGBA); ok {
		i := rgba.PixOffset(x, y)
		switch ch {
		case imageChannelR:
			return rgba.Pix[i]
		case imageChannelG:
			return rgba.Pix[i+1]
		case imageChannelB:
			return rgba.Pix[i+2]
		case imageChannelA:
			return rgba.Pix[i+3]
		}
		return 0
	}
	if cmyk, ok := img.(*image.CMYK); ok {
		switch ch {
		case imageChannelC:
			return cmyk.CMYKAt(x, y).C
		case imageChannelM:
			return cmyk.CMYKAt(x, y).M
		case imageChannelY:
			return cmyk.CMYKAt(x, y).Y
		case imageChannelK:
			return cmyk.CMYKAt(x, y).K
		}
		return 0
	}
	r, g, b, a := img.At(x, y).RGBA()
	switch ch {
	case imageChannelR:
		return uint8(r >> 8)
	case imageChannelG:
		return uint8(g >> 8)
	case imageChannelB:
		return uint8(b >> 8)
	case imageChannelA:
		return uint8(a >> 8)
	}
	return 0
}

// imageChannels returns the set of channels we may reference. CMYK images get
// 8 channels, everything else gets 4 (RGBA).
func imageChannels(img image.Image) []uint8 {
	ch := []uint8{imageChannelR, imageChannelG, imageChannelB, imageChannelA}
	if _, ok := img.(*image.CMYK); ok {
		ch = append(ch, imageChannelC, imageChannelM, imageChannelY, imageChannelK)
	}
	return ch
}

// rngChannelOrder fills the given buffer (length n, n <= 8) with a random
// permutation of [0,n) for trying channels in random order without allocating.
func rngChannelOrder(rng *fastRNG, order []int, n int) {
	for i := 0; i < n; i++ {
		order[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := rng.IntN(i + 1)
		order[i], order[j] = order[j], order[i]
	}
}