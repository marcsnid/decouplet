package decouplet

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var (
	ErrorMatchNotFound         = errors.New("match not found")
	ErrorDecodeNotFound        = errors.New("valid decode character not found")
	ErrorKeyCastFailed         = errors.New("failed to cast key")
	ErrorDecodeGeneric         = errors.New("decode error")
	ErrorDecodeGroup           = errors.New("decode groups missing locations")
	ErrorInvalidKey            = errors.New("invalid key")
	ErrorBytesInvalidKeyLength = errors.New("invalid key length, must be between 32 and 64 bytes")
	ErrorImageKeyTooSmall      = errors.New("key needs to be larger than 300x300")
)

const (
	stxByte byte = 0x02 // Start of Text
	etxByte byte = 0x03 // End of Text
)

type Encoder interface {
	Encode(io.Reader, io.Writer) error
	Decode(io.Reader, io.Writer) error
	Validate() error
}

func startEncode(w io.Writer) error {
	_, err := w.Write([]byte{stxByte})
	return err
}

func finishEncode(w io.Writer) error {
	_, err := w.Write([]byte{etxByte})
	return err
}

func readAndVerifyStart(r io.Reader) error {
	start := make([]byte, 1)
	if _, err := io.ReadFull(r, start); err != nil {
		return err
	}
	if start[0] != stxByte {
		return ErrorDecodeNotFound
	}
	return nil
}

func readAndCheckETX(r io.Reader, buffer []byte, recordSize int) (bool, error) {
	n, err := io.ReadFull(r, buffer[:recordSize])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// If we only got 1 byte and it's ETX, that's the end
		if n == 1 && buffer[0] == etxByte {
			return true, nil
		}
		if n == 0 {
			return false, io.EOF
		}
		return false, ErrorDecodeNotFound
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func getRandomInt(max int64) (int, error) {
	bMax := big.NewInt(max)
	n, err := rand.Int(rand.Reader, bMax)
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func getRandomPair(bounds int64) (int, int, error) {
	x1, err := getRandomInt(bounds)
	if err != nil {
		return 0, 0, err
	}
	x2, err := getRandomInt(bounds)
	if err != nil {
		return 0, 0, err
	}
	return x1, x2, nil
}

func checkMatch(b byte, x, y uint16) (bool, uint8) {
	for supplement := 0; supplement < 256; supplement++ {
		if b == byte((x-y+uint16(supplement)+256)%256) {
			return true, uint8(supplement)
		}
	}
	return false, 0
}
