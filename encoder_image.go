package decouplet

import (
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

	imageEncodedSize          = 10 // Each image encoding is 10 bytes
	imageMatchFindRetries int = 4
	imageKeySize          int = 300
	imageCheckedMax       int = 46368
	imageRetriesPerByte   int = 150000
)

// ImageEncoder is an implementation of the Encoder that uses image.Image as a key
// It encodes and decodes data by using pixel values in the image.
type imageEncoder struct {
	Key image.Image
}

func NewImageEncoder(key image.Image) Encoder {
	return &imageEncoder{Key: key}
}

func (i *imageEncoder) Encode(r io.Reader, w io.Writer) error {
	err := i.Validate()
	if err != nil {
		return err
	}
	return i.encode(r, w)
}

// encode is the main encoding function for the image encoder.
func (i *imageEncoder) encode(r io.Reader, w io.Writer) error {
	bounds := i.Key.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	err := startEncode(w)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			checks := 0
			for idx := 0; idx < n; idx++ {
				for {
					if checks >= imageRetriesPerByte {
						return ErrorMatchNotFound
					}
					checks++
					x1, x2, err := getRandomPair(int64(width))
					if err != nil {
						return err
					}
					y1, y2, err := getRandomPair(int64(height))
					if err != nil {
						return err
					}
					found, channel, supplement, err := getImagePixelMatch(buf[idx], i.Key, int64(x1), int64(y1), int64(x2), int64(y2))
					if err != nil {
						return err
					}
					if found {
						err = encodeImage(uint16(x1), uint16(y1), uint16(x2), uint16(y2), channel, supplement, w)
						if err != nil {
							return err
						}
						break
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return finishEncode(w)
}

func (i *imageEncoder) Decode(r io.Reader, w io.Writer) error {
	err := i.Validate()
	if err != nil {
		return err
	}
	return i.decode(r, w)
}

// decode is the main decoding function for the image encoder.
func (i *imageEncoder) decode(r io.Reader, w io.Writer) error {
	err := readAndVerifyStart(r)
	if err != nil {
		return err
	}

	buffer := make([]byte, imageEncodedSize)
	for {
		end, err := readAndCheckETX(r, buffer, imageEncodedSize)
		if err != nil {
			return err
		}
		if end {
			break
		}

		x1 := binary.BigEndian.Uint16(buffer[0:2])
		y1 := binary.BigEndian.Uint16(buffer[2:4])
		x2 := binary.BigEndian.Uint16(buffer[4:6])
		y2 := binary.BigEndian.Uint16(buffer[6:8])
		channel := buffer[8]
		supplement := buffer[9]

		var v1, v2 uint32
		if cmykImg, ok := i.Key.(*image.CMYK); ok {
			c1, m1, y1c, k1 := cmykImg.CMYKAt(int(x1), int(y1)).C,
				cmykImg.CMYKAt(int(x1), int(y1)).M,
				cmykImg.CMYKAt(int(x1), int(y1)).Y,
				cmykImg.CMYKAt(int(x1), int(y1)).K
			c2, m2, y2c, k2 := cmykImg.CMYKAt(int(x2), int(y2)).C,
				cmykImg.CMYKAt(int(x2), int(y2)).M,
				cmykImg.CMYKAt(int(x2), int(y2)).Y,
				cmykImg.CMYKAt(int(x2), int(y2)).K
			switch channel {
			case imageChannelC:
				v1, v2 = uint32(c1), uint32(c2)
			case imageChannelM:
				v1, v2 = uint32(m1), uint32(m2)
			case imageChannelY:
				v1, v2 = uint32(y1c), uint32(y2c)
			case imageChannelK:
				v1, v2 = uint32(k1), uint32(k2)
			}
		} else {
			r1, g1, b1, a1 := i.Key.At(int(x1), int(y1)).RGBA()
			r2, g2, b2, a2 := i.Key.At(int(x2), int(y2)).RGBA()
			switch channel {
			case imageChannelR:
				v1, v2 = r1>>8, r2>>8
			case imageChannelG:
				v1, v2 = g1>>8, g2>>8
			case imageChannelB:
				v1, v2 = b1>>8, b2>>8
			case imageChannelA:
				v1, v2 = a1>>8, a2>>8
			}
		}

		decoded := byte((int(v1) - int(v2) + int(supplement) + 256) % 256)
		if _, err := w.Write([]byte{decoded}); err != nil {
			return err
		}
	}
	return nil
}

func (i *imageEncoder) Validate() error {
	if i.Key == nil {
		return ErrorInvalidKey
	}
	if i.Key.Bounds().Max.X < imageKeySize || i.Key.Bounds().Max.Y < imageKeySize {
		return ErrorImageKeyTooSmall
	}
	return nil
}

func getImagePixelMatch(b byte, key image.Image, x1 int64, y1 int64, x2 int64, y2 int64) (bool, uint8, uint8, error) {
	r1, g1, b1, a1 := key.At(int(x1), int(y1)).RGBA()
	r2, g2, b2, a2 := key.At(int(x2), int(y2)).RGBA()
	cmykImage, ok := key.(*image.CMYK)
	var c1, m1, y1c, k1, c2, m2, y2c, k2 uint8
	channels := []uint8{imageChannelR, imageChannelG, imageChannelB, imageChannelA}
	if ok {
		channels = append(channels, imageChannelC, imageChannelM, imageChannelY, imageChannelK)
		c1, m1, y1c, k1 = cmykImage.CMYKAt(int(x1), int(y1)).C, cmykImage.CMYKAt(int(x1), int(y1)).M, cmykImage.CMYKAt(int(x1), int(y1)).Y, cmykImage.CMYKAt(int(x1), int(y1)).K
		c2, m2, y2c, k2 = cmykImage.CMYKAt(int(x2), int(y2)).C, cmykImage.CMYKAt(int(x2), int(y2)).M, cmykImage.CMYKAt(int(x2), int(y2)).Y, cmykImage.CMYKAt(int(x2), int(y2)).K
	}

	for len(channels) > 0 {
		idx, err := getRandomInt(int64(len(channels)))
		if err != nil {
			return false, 0, 0, err
		}
		switch channels[idx] {
		case imageChannelR:
			match, supplement := checkMatch(b, uint16(r1>>8), uint16(r2>>8))
			if match {
				return true, imageChannelR, supplement, nil
			}
		case imageChannelG:
			match, supplement := checkMatch(b, uint16(g1>>8), uint16(g2>>8))
			if match {
				return true, imageChannelG, supplement, nil
			}
		case imageChannelB:
			match, supplement := checkMatch(b, uint16(b1>>8), uint16(b2>>8))
			if match {
				return true, imageChannelB, supplement, nil
			}
		case imageChannelA:
			match, supplement := checkMatch(b, uint16(a1>>8), uint16(a2>>8))
			if match {
				return true, imageChannelA, supplement, nil
			}
		case imageChannelC:
			match, supplement := checkMatch(b, uint16(c1), uint16(c2))
			if match {
				return true, imageChannelC, supplement, nil
			}
		case imageChannelM:
			match, supplement := checkMatch(b, uint16(m1), uint16(m2))
			if match {
				return true, imageChannelM, supplement, nil
			}
		case imageChannelY:
			match, supplement := checkMatch(b, uint16(y1c), uint16(y2c))
			if match {
				return true, imageChannelY, supplement, nil
			}
		case imageChannelK:
			match, supplement := checkMatch(b, uint16(k1), uint16(k2))
			if match {
				return true, imageChannelK, supplement, nil
			}
		}
		channels = append(channels[:idx], channels[idx+1:]...)
	}
	return false, 0, 0, nil
}

func encodeImage(x1, y1, x2, y2 uint16, channel, supplement uint8, w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, x1)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, y1)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, x2)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, y2)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, channel)
	if err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, supplement)
}
