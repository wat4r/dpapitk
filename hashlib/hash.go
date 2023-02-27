package hashlib

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

func New(name string, data []byte) []byte {
	var hashFunc func() hash.Hash

	switch strings.ToLower(name) {
	case "md4":
		hashFunc = md4.New
	case "sha1":
		hashFunc = sha1.New
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	}

	h := hashFunc()
	h.Write(data)
	return h.Sum(nil)
}

/*
	 Implementation of PBKDF2 that allows specifying digest algorithm.
		Returns the corresponding expanded key which is keylen long.
		Note: This is not real pbkdf2, but instead a slight modification of it.
		Seems like Microsoft tried to implement pbkdf2 but got the xoring wrong.
*/
func Pbkdf2Ms(passphrase, salt []byte, keyLen, iterations int, digest string) []byte {
	var buff []byte
	i := 1
	for len(buff) < keyLen {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint32(i))
		msg := append(salt, buf.Bytes()...)
		i += 1

		derived := Hmac(passphrase, msg, digest)
		for i := 0; i < iterations-1; i++ {
			actual := Hmac(passphrase, derived, digest)

			derivedNew := make([]byte, len(derived))
			for j := range derived {
				derivedNew[j] = derived[j] ^ actual[j]
			}
			derived = derivedNew
		}
		buff = append(buff, derived...)
	}
	return buff[:keyLen]
}

/*
	 Implementation of PBKDF2 that allows specifying digest algorithm.
		   Returns the corresponding expanded key which is keylen long.
*/
func Pbkdf2(passphrase, salt []byte, keyLen, iterations int, digest string) (result []byte) {
	var hashFunc func() hash.Hash
	switch strings.ToLower(digest) {
	case "sha1":
		hashFunc = sha1.New
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	}
	result = pbkdf2.Key(passphrase, salt, iterations, keyLen, hashFunc)[:keyLen]
	return
}
