# decouplet

A Go library for decoupling bytes using variable-length keys.
decouplet transforms input bytes by referencing a key and calculating deltas,
producing output that represents measurements relative to that key; effectively
removing any inherent meaning from the original message without the key.

[![GoDoc](https://godoc.org/github.com/marcsnid/decouplet?status.svg)](https://godoc.org/github.com/marcsnid/decouplet)

### Encoder Types

Type | Key | Delta| Encoded Size per Byte
-----|-----|------|-----
Image|image.Image|Pixel values in RGBA and CMYK|~9 bytes
Byte |[]byte|Standard byte-wise delta calculations|~3 bytes (small key) / ~5 bytes (large key)

Note: Each input byte is enlarged to their respective encoded size, plus a
2-byte header, a 1-byte end marker, and a 16-byte keyed checksum.

### Use Cases

While not encryption, decouplet gives you output that does not resemble
the input: the same plaintext produces different records every time, and the
same byte is represented by many different records. The output is larger than
the input, about 3x for the byte encoder and 9x for the image encoder.

You can use decouplet with already-encrypted data, or further encrypt its
output for additional obfuscation. A keyed checksum is included so the decoder
can detect tampering and reject the wrong key.

### Installation

```sh
go get -u github.com/marcsnid/decouplet
```

### Usage

```go
import "github.com/marcsnid/decouplet"

// Byte encoder: key must be 32-512 bytes and varied enough that every byte
// value 0-255 can be represented as a difference of two key positions.
key := make([]byte, 256)
// fill key...
enc := decouplet.NewByteEncoder(key)

var out bytes.Buffer
err := enc.Encode(bytes.NewReader(data), &out)

var back bytes.Buffer
err = enc.Decode(bytes.NewReader(out.Bytes()), &back)

// Image encoder: key image must be at least 300x300. Load it with LoadImage.
img, err := decouplet.LoadImage("key.png")
imgEnc := decouplet.NewImageEncoder(img)
```

A wrong key or a tampered stream returns `ErrorTamper`. A truncated stream or a
bad framing byte returns `ErrorTruncated`. An unknown version returns
`ErrorUnknownVersion`. A key that cannot represent all 256 byte values returns
`ErrorKeyTooSparse` from `Validate`.

### Testing

```sh
go test ./...
go test -bench=. ./...
```

Image tests use synthetic images and do not require any asset files.

### Credit

Idea based on DVNC Whitepaper by Joseph Lloyd, licensed under FDL 1.3