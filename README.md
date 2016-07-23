# pepperpickle


## Synopsis

PEPPERPICKLE is a small program that can be used to secretly store a file into an image file.

The hidden file is encrypted using AES256 and stored steganographically in the image. A hidden file can be any file, provided it is significantly smaller than the cover image (i.e. the image file it is stored in).

Supported input formats for the cover image are PNG, JPG and GIF. As output, only PNG is supported.

Currently, the message is stored using the LSB (Least Significant Bit) of the pixel data. The ability to use more LSBs and the addition of algorithms that increase the storage capability of an image are planned for a future release.

Please report any bugs you might find. Suggestions and feature requests are welcome.


## Installation

Binaries for Linux-amd64 and Mac OS X are available at:
[https://github.com/w33zl3p00tch/pepperpickle/releases]

Simply extract the binary to a folder in your PATH, e.g. /usr/local


pepperpickle is written in Go 1.6. To successfully compile it, "golang.org/x/crypto/scrypt" and "golang.org/x/crypto/ssh/terminal" are needed.

You can install the additional libraries by issuing:

```$ go get golang.org/x/crypto/scrypt```

```$ go get golang.org/x/crypto/ssh/terminal```

or just clone the repo:
git clone https://go.googlesource.com/crypto

see https://go.googlesource.com/crypto for further information


## Usage

to encrypt a file into an image:

```pepperpickle -encrypt FILE_TO_HIDE -image IMAGE```



to decrypt a file:

```pepperpickle -decrypt IMAGE_out.png```

The user will be asked to provide a password.


## Revision history

v0.0.2: added workaround for images with fully transparent sections

v0.0.1: initial commit


## Known issues

pepperpickle_0: on some pixels with a green value of 255 in images with transparency the green value is set to 1. Apparently this is not an overflow bug in pepperpickle itself. I am investigating the issue. Any help is greatly appreciated.


## License

Pepperpickle is released under a BSD-Style license.
