/*
pepperpickle

version 0.0.1 - initial published version


2016 Manuel Iwansky ( w33zl3p00tch [at) gmail d0t com )
released under a BSD-Style license
*/

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal" // to get password without echo
	"image"
	"image/color"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	_"image/gif"
	_"image/jpeg"
)

func main() {
	// flags
	encryptPtr := flag.String("encrypt", "",
		"name of the file to encrypt")
	decryptPtr := flag.String("decrypt", "",
		"name of the image to decrypt")
	imagePtr := flag.String("image", "",
		"name of the source image")
	flag.Parse()

	encFile := *encryptPtr
	decFile := *decryptPtr
	imgFile := *imagePtr

	const b_len = 8 // length of on byte in bits

	// Encrypt encFile and store it in imgFile if both flags are set:
	if encFile != "" && imgFile != "" {

		// Open the image
		infile, err := os.Open(imgFile)
		check(err)
		defer infile.Close()

		src, _, err := image.Decode(infile)
		check(err)

		// Open the message file
		fmt.Println("Opening the message file...")
		msgfile, err := ioutil.ReadFile(encFile)
		check(err)
		msgFilename := filepath.Base(encFile)

		// Compress the message
		fmt.Println("Trying to compress the message... ")
		msg := compress(msgfile)
		fmt.Println("done.")

		// Assemble the message:
		// Add header: the header consists of a magic number, the filesize,
		// the filename's size and the filename.
		msgFull := assemble(msg, msgFilename)

		// Check if the message fits into the image:
		bounds := src.Bounds()
		w, h := bounds.Max.X, bounds.Max.Y
		maxMsgSize := w * h * 3

		fmt.Printf("Size of full message:\t")
		fmt.Println(len(msgFull) + 16 + 16)
		if len(msgFull)+32 > maxMsgSize/8 {
			log.Fatal("Sorry, the compressed message is too large.")
		}

		// Get the encryption password from the user
		password := getPassword()

		// Encrypt the message:
		passwd := password
		bitstring := encryptToB(msgFull, passwd, maxMsgSize)

		// Encode the message:
		dest, err := imgEncode(src, bitstring)

		// Save the resulting image:
		extName := filepath.Ext(imgFile)
		fileName := filepath.Base(imgFile)
		outfileName := fileName[:len(fileName)-len(extName)]


		fmt.Printf("Encoding and saving the image... ")
		outfile, err := os.Create(outfileName + "_out.png")
		check(err)
		defer outfile.Close()
		png.Encode(outfile, dest)
		fmt.Println("done.\n\n" + outfileName + "_out.png written.")

		} else if decFile != "" { // Decrypt decFile, a png image:
		// Open the image:
		infile1, err := os.Open(decFile)
		check(err)
		defer infile1.Close()

		cryptsrc, err := png.Decode(infile1)
		check(err)

		// Decode the message:
		msgOut := imgDecode(cryptsrc)

		msgOut_b := make([]byte, len(msgOut)/b_len)
		for i, k := 0, 0; i < (len(msgOut) - (b_len - 1)); i += b_len {
			currentByte, _ := strconv.ParseInt(msgOut[i:i+b_len], 2, 16)
			msgOut_b[k] = uint8(currentByte)
			k++
		}

		// Decrypt the message:
		// The first 16bytes  should contain the salt
		salt := msgOut_b[0:16]
		ciphertext := msgOut_b[16:]

		passwd := getDecPassword()

		plaintext := decryptFromB(ciphertext, passwd, salt)

		magic := plaintext[0:5]
		if !bytes.Equal(magic, []byte{208, 110, 250, 206, 1}) {
			fmt.Println("Error after decoding. Wrong Password?")
			return
		}
		filenamesize := uint64(plaintext[5])
		filesize_b := plaintext[6:14]
		var filesize uint64
		buf := bytes.NewBuffer(filesize_b)
		binary.Read(buf, binary.BigEndian, &filesize)

		filename := string(plaintext[14 : 14+filenamesize])
		fmt.Printf("Filename of the encrypted file:\t")
		fmt.Println(filename)

		msgCompr := plaintext[14+filenamesize : 14+filenamesize+filesize]

		msg := decompress(msgCompr)

		// Save the file
		outfile, err := os.Create(filename)
		check(err)

		defer outfile.Close()

		outfile.Write(msg)
		outfile.Sync()

		fmt.Println(filename + " written.")

	} else {
		fmt.Println("\n\nYou have to set either -encrypt and -image or -decrypt." +
			"\n\nExample usage:\n\"" + os.Args[0] + " -encrypt FILE_TO_ENCRYPT " +
			"-image IMAGE_TO_STORE_THE_FILE\" to encrypt a file\nor:\n\"" +
			os.Args[0] + " -decrypt image_to_decrypt\" to decrypt\n\n")
	}
}


// Check for errors and quit if an error occured.
func check(err error) {
        if err != nil {
                log.Fatal(err)
        }
}

// Get the password from the user. Will not echo.
func getPassword() string {
	var password string
	match := false

	for match == false {
		fmt.Print("\n\nEnter a password for encryption: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		check(err)

		fmt.Print("\n\nPlease verify the password: ")
		bytePassword1, err := terminal.ReadPassword(int(syscall.Stdin))
		check(err)

		if bytes.Equal(bytePassword, bytePassword1) {
			match = true
			password = string(bytePassword)

		} else {
			fmt.Println("\n\n\nSorry - passwords don't match." +
				" Please try again.")
		}
	}

	return password
}

// Get the password for decryption. No need to verify this time.
func getDecPassword() string {
	var password string

	fmt.Print("\n\nEnter password for decryption: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	check(err)

	password = string(bytePassword)

	return password
}

// compress the message
func compress(input []byte) []byte {
	var buf bytes.Buffer
	compr := zlib.NewWriter(&buf)
	compr.Write(input)
	compr.Close()
	output := buf.Bytes()

	return output
}

// decompress the message
func decompress(input []byte) []byte {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	b := bytes.NewReader(input)
	r, err := zlib.NewReader(b)
	check(err)
	io.Copy(w, r)
	r.Close()
	output := buf.Bytes()
	fmt.Printf("Size of output: ")
	fmt.Println(len(output))

	return output
}

// Assemble the message:
func assemble(msg []byte, msgFilename string) []byte {
	// Format:
	// [magic, 5b] [filename size, 1b] [message size, 8b] [filename] [message...]

	// The magic number will indicate that the message is decoded correctly.
	// The last byte is reserved for future additions. 01 inidcates
	// the first version of the format.
	magic := []byte{0xD0, 0x6E, 0xFA, 0xCE, 0x01} // D0 6E FA CE 01

	msgFilename_b := []byte(msgFilename)

	msgNameSize := []byte{byte(len(msgFilename_b))}

	// Message Size - Needed to correctly extract the message part
	var tmpSize uint64 = uint64(len(msg))
	msgSize := make([]byte, 8)
	binary.BigEndian.PutUint64(msgSize, uint64(tmpSize))

	// Concatenate the different arrays to msgFull
	msgHead0 := append(magic, msgNameSize...)
	msgHead1 := append(msgHead0, msgSize...)
	msgHeader := append(msgHead1, msgFilename_b...)
	msgFull := append(msgHeader, msg...)

	return msgFull
}

// encryptToB encrypts the message to a string of binary data.
// Format: [salt, 16bytes] [ciphertext] [randomly generated padding]
func encryptToB(plaintext []byte, passwd string, maxMsgSize int) string {
	var ciphertext []byte

	salt, err := generateRandomBytes(16)
	key := getKey(passwd, salt) //get a 32byte key to make use of AES256

	if ciphertext, err = encrypt(key, plaintext); err != nil {
		log.Fatal(err)
	}

	// prepend the salt
	ciphertext_s := append(salt, ciphertext...)

	// check whether the message still fits into the image

	fmt.Printf("Max. message size:\t")
	fmt.Println(maxMsgSize / 8)
	if len(ciphertext_s)*8 > maxMsgSize {
		panic("Sorry, the message to encrypt is too large.")
	}

	// fill the remaining space with random bytes
	paddingSize := ((maxMsgSize + (maxMsgSize % 8)) - (len(ciphertext_s) * 8)) / 8

	padding, err := generateRandomBytes(paddingSize)
	check(err)

	ciphertextFull := append(ciphertext_s, padding...)

	// Encode to binary
	bitstring := bToBit(ciphertextFull)

	return bitstring
}

// wrapper to recreate the key and decrypt the ciphertext
func decryptFromB(ciphertext []byte, passwd string, salt []byte) []byte {
	key := getKey(passwd, salt)
	plaintext, _ := decrypt(key, ciphertext)

	return plaintext
}

// encrypt AES. The key has to be 32 bytes long for AES256.
func encrypt(key, text []byte) (ciphertext []byte, err error) {
	fmt.Printf("\nEncrypting... ")
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	fmt.Println("done.")
	return
}

// decrypt AES
func decrypt(key, ciphertext []byte) (plaintext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

// generateRandomBytes returns an array of random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	check(err)

	return b, nil
}

// imgEncode takes an image and a string of ones and zeros as input and
// encodes the string into the image. This is done by setting the Least
// Significant Bit (LSB) of the current pixel's color values to either 1 or 0,
// according to the binary representation of the message in the bitstring.
// 	The alpha value is left as it is for two reasons:
// first, there is no alpha value in e.g. JPEGs. Secondly, in most images it
// will always be set to opaque, making detection of steganography too easy.
// This is a little bit sad, as using the alpha value would give us one more
// bit of storage for each pixel. - Thus, it's exactly one little bit sad ;)
func imgEncode(src image.Image, bitstring string) (image.Image, error) {
	fmt.Printf("Encoding the message... ")
	bounds := src.Bounds()
	w, h := bounds.Max.X, bounds.Max.Y
	dest := image.NewRGBA(image.Rect(0, 0, w, h))
	bitindex := 0

	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			pixel := src.At(x, y)
			//bitindex := (x + y) * 3

			// pixel.RGBA returns uint64, so the values are divided
			// to uint8 (one byte) to make them suitable for
			// image.Set() and manipulation of the LSB.
			srcr, srcg, srcb, alph := pixel.RGBA()
			tmpr := uint8(srcr / 256)
			tmpg := uint8(srcg / 256)
			tmpb := uint8(srcb / 256)

			// 48 is "0", 49 is "1" in ASCII/UTF8
			if bitstring[bitindex] == 48 && tmpr%2 == 1 {
				tmpr--
			} else if bitstring[bitindex] == 49 && tmpr%2 == 0 {
				tmpr++
			}
			if bitstring[bitindex+1] == 48 && tmpg%2 == 1 {
				tmpg--
			} else if bitstring[bitindex+1] == 49 && tmpg%2 == 0 {
				tmpg++
			}
			if bitstring[bitindex+2] == 48 && tmpb%2 == 1 {
				tmpb--
			} else if bitstring[bitindex+2] == 49 && tmpb%2 == 0 {
				tmpb++
			}
			dest.Set(x, y, color.RGBA{tmpr, tmpg, tmpb, uint8(alph / 256)})
			bitindex += 3
		}
	}
	fmt.Println("done.")

	return dest, nil
}

func imgDecode(src image.Image) string {
	fmt.Printf("Decoding the message... ")
	bounds := src.Bounds()
	w, h := bounds.Max.X, bounds.Max.Y
	msgOut := make([]byte, w*h*3)
	bitindex := 0

	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			pixel := src.At(x, y)
			//bitindex := (x + y) * 3

			// pixel.RGBA returns uint64, so the values are divided
			// to uint8 (one byte) to make them suitable for reading.
			srcr, srcg, srcb, _ := pixel.RGBA()
			tmpr := uint8(srcr / 256)
			tmpg := uint8(srcg / 256)
			tmpb := uint8(srcb / 256)

			if tmpr%2 == 0 {
				msgOut[bitindex] = 48
			} else {
				msgOut[bitindex] = 49
			}
			if tmpg%2 == 0 {
				msgOut[bitindex+1] = 48
			} else {
				msgOut[bitindex+1] = 49
			}
			if tmpb%2 == 0 {
				msgOut[bitindex+2] = 48
			} else {
				msgOut[bitindex+2] = 49
			}

			bitindex += 3
		}
	}
	fmt.Println("done.")

	return string(msgOut)
}

// bToBit takes an array of bytes as input and converts it to a string in
// its binary representation, where every 8 bits represent one byte.
func bToBit(bytesIn []byte) string {

	var buffer bytes.Buffer

	fmt.Printf("Converting to binary... ")
	const b_len = 8 // Length of one byte in bits.
	// This probably won't change :)

	length_b := len(bytesIn)

	for i := 0; i < length_b; i++ {
		// convert the current byte to binary
		currentByte := strconv.FormatInt(int64(bytesIn[i]), 2)

		// add padding in front of currentByte, if necessary.
		// e.g.: when currentByte == "101", add zeros until
		// currentByte == "00000101". This ensures that the
		// output is evenly divisible by 8, i.e. every
		// byte is represented by a group of 8 bits.
		// The string representation will be in ASCII/UTF8,
		// which means that "0" has a value of 48, whereas
		// "1" has a value of 49.
		for len(currentByte) < b_len {
			currentByte = "0" + currentByte
		}
		buffer.WriteString(currentByte)
	}
	fmt.Println("done.")

	return buffer.String()
}

// getKey generates a 256bit (len 32) key from the password using
// the salt. This key, in conjunction with crypto/aes, ensures that
// AES256 is used. getKey relies upon golang.org/x/crypto/scrypt
func getKey(psw string, salt []byte) []byte {
	dk, err := scrypt.Key([]byte(psw), salt, 32768, 8, 2, 32)
	check(err)

	return dk
}
