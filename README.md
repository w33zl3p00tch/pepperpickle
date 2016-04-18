# pepperpickle

## Synopsis

PEPPERPICKLE is a small program that can be used to secretly store a file into an image file.

The hidden file is encrypted using AES256 and stored steganographically in the image. A hiddenfile can be any file, provided it is significantly smaller than the cover image (i.e. the image file it is stored in).

Supported input formats for the cover image are PNG, JPG and GIF. As output, only PNG is supported.

Currently, the message is stored using the LSB (Least Significant Bit) of the pixel data.

## Installation

pepperpickle is written in Go 1.6. To successfully compile it, "golang.org/x/crypto/scrypt" and "golang.org/x/crypto/ssh/terminal" are needed.

## Usage

to encrypt a file into an image:
```pepperpickle -encrypt FILE_TO_HIDE -image IMAGE```

to decrypt a file:
```pepperpickle -decrypt IMAGE_out.png```

The user will be asked to provide a password.

## Revision history

ver. 0.0.1: initial commit

## License

Pepperpickle is released under a BSD-Style license.
