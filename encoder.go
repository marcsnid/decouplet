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
	imageMatchFindRetries int  = 4
	imageKeySize          int  = 300
	imageCheckedMax       int  = 46368
	imageRetriesPerByte   int  = 150000
	stxByte               byte = 0x02 // Start of Text
	etxByte               byte = 0x03 // End of Text
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

func checkForETX(r io.Reader, buffer []byte) (bool, error) {
	peek := make([]byte, 1)
	defer func() { buffer[0] = peek[0] }()
	n, err := r.Read(peek)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if peek[0] == etxByte {
		return true, nil
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

func checkMatch(b byte, x, y uint16) (bool, uint8) {
	for supplement := 0; supplement < 256; supplement++ {
		if b == byte((x-y+uint16(supplement)+256)%256) {
			return true, uint8(supplement)
		}
	}
	return false, 0
}
