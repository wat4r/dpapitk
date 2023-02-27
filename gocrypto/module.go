package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"strings"
)

func ModuleDecrypt(ciphertext []byte, key []byte, module string, mode string, iv []byte) []byte {
	var plaintext []byte
	var err error
	switch strings.ToUpper(module) {
	case "AES":
		plaintext, err = aesDecrypt(ciphertext, key, iv, mode)
	case "3DES":
		plaintext, err = tripleDesDecrypt(ciphertext, key, iv, mode)
	}
	if err != nil {
		return nil
	}
	return plaintext
}

func aesDecrypt(ciphertext []byte, key []byte, iv []byte, mode string) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	switch strings.ToUpper(mode) {
	case "CBC":
		m := cipher.NewCBCDecrypter(block, iv)
		m.CryptBlocks(plaintext, ciphertext)
	case "CFB":
		m := cipher.NewCFBDecrypter(block, iv)
		m.XORKeyStream(plaintext, ciphertext)
	}

	return plaintext, nil
}

func tripleDesDecrypt(ciphertext, key []byte, iv []byte, mode string) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	switch strings.ToUpper(mode) {
	case "CBC":
		m := cipher.NewCBCDecrypter(block, iv)
		m.CryptBlocks(plaintext, ciphertext)
	case "CFB":
		m := cipher.NewCFBDecrypter(block, iv)
		m.XORKeyStream(plaintext, ciphertext)
	}

	return plaintext, nil
}
