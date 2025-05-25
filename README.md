# decouplet

A cryptographic library in Go for decoupling bytes using variable-length keys.  
decouplet transforms input bytes by referencing a key and calculating deltas,  
producing output that represents measurements relative to that key; effectively  
removing any inherent meaning from the original message without the key.

[![GoDoc](https://godoc.org/github.com/marcsnid/decouplet?status.svg)](https://godoc.org/github.com/marcsnid/decouplet)

### Encoder Types

Type | Key | Delta| Encoded Size per Byte
-----|-----|------|-----
Image|image.Image|Pixel values in RGBA and CMYK|10 bytes
Byte |[]byte|Standard byte-wise delta calculations|5 bytes

Note: Each input byte size is enlarged to their respective encoded size, plus an additional 2 bytes for the start and end markers.

### Use Cases

While not a traditional encryption method, decouplet offers similar benefits.  
It is best suited for small messages or passwords: the process provides a high  
level of decoupling, but generates relatively large output.

You can also use decouplet with already-encrypted data, or further encrypt its  
output for additional obfuscation.

### Installation

```sh
go get -u github.com/marcsnid/decouplet
```

### Testing

Place images named `test.png`, `test2.png`, `tux.ppm` in the decouplet folder.

### Credit

Idea based on *DVNC Whitepaper* by Joseph Lloyd, licensed under FDL 1.3
