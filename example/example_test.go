package example

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"testing"

	"github.com/marcsnid/decouplet"
)

func Test_AESExample(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Error(err)
	}
	unencrypted := []byte("This is an example message to encode.")
	encryptedBytes, nonce, err := aesEncrypt(unencrypted, key)
	if err != nil {
		t.Error(err)
	}
	log.Println("Encrypted message:", string(encryptedBytes))
	encodeKey := []byte("This is an example key!@#$%^&*()1234567890")
	output, err := decouplet.EncodeBytes(encryptedBytes, encodeKey)
	if err != nil {
		t.Error(err)
	}
	log.Println("Encoded message:", string(output))
	decoded, err := decouplet.DecodeBytes(output, encodeKey)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decoded, encryptedBytes) {
		t.Log("decoded bytes do not equal encrypted bytes")
		t.Fail()
	}
	decrypted, err := aesDecrypt(decoded, key, nonce)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, unencrypted) {
		t.Log("Decrypted text does not equal original text")
		t.Fail()
	}
	log.Println("Decrypted text:", string(decrypted))
}
