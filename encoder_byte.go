package decouplet

import (
	"encoding/binary"
	"io"
)

const (
	byteRetriesPerByte = 1000 // Number of retries to find a match for each byte
	byteEncodedSize    = 5    // Each byte is encoded as 5 bytes
	byteMaxKeySize     = 512  // Maximum key size for byte encoder
	byteMinKeySize     = 32   // Minimum key size for byte encoder
)

// ByteEncoder is an implementation of the Encoder that uses a byte slice as a key
type byteEncoder struct {
	Key []byte
}

func NewByteEncoder(key []byte) Encoder {
	return &byteEncoder{Key: key}
}

func (b *byteEncoder) Encode(r io.Reader, w io.Writer) error {
	err := b.Validate()
	if err != nil {
		return err
	}
	return b.encode(r, w)
}

// encode is the main encoding function for the byte encoder.
func (b *byteEncoder) encode(r io.Reader, w io.Writer) error {
	bounds := len(b.Key)

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
				found := false
				for !found {
					checks++
					if checks >= byteRetriesPerByte {
						return ErrorMatchNotFound
					}
					x1, x2, err := getRandomPair(int64(bounds))
					if err != nil {
						return err
					}
					match, supplement := checkMatch(buf[idx], uint16(x1), uint16(x2))
					if match {
						err = encodeByte(uint16(x1), uint16(x2), uint8(supplement), w)
						if err != nil {
							return err
						}
						found = true
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

func (b *byteEncoder) Decode(r io.Reader, w io.Writer) error {
	err := b.Validate()
	if err != nil {
		return err
	}
	return b.decode(r, w)
}

// decode is the main decoding function for the byte encoder.
func (b *byteEncoder) decode(r io.Reader, w io.Writer) error {
	err := readAndVerifyStart(r)
	if err != nil {
		return err
	}

	buffer := make([]byte, byteEncodedSize)
	for {
		end, err := checkForETX(r, buffer)
		if err != nil {
			return err
		}
		if end {
			break
		}

		// Read remaining bytes for each encoded byte
		if _, err := io.ReadFull(r, buffer[1:]); err != nil {
			return err
		}
		x1 := binary.BigEndian.Uint16(buffer[0:2])
		x2 := binary.BigEndian.Uint16(buffer[2:4])
		supplement := buffer[4]
		decoded := byte((int(x1) - int(x2) + int(supplement) + 256) % 256)
		if _, err := w.Write([]byte{decoded}); err != nil {
			return err
		}
	}
	return nil
}

func (b *byteEncoder) Validate() error {
	if len(b.Key) == 0 {
		return ErrorInvalidKey
	}
	if len(b.Key) < byteMinKeySize || len(b.Key) > byteMaxKeySize {
		return ErrorBytesInvalidKeyLength
	}
	return nil
}

func encodeByte(x1, x2 uint16, supplement uint8, w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, x1)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, x2)
	if err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, supplement)
}
