package hashlib

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func Hmac(key, msg []byte, digestmod string) []byte {
	var hashFunc func() hash.Hash
	switch strings.ToLower(digestmod) {
	case "sha1":
		hashFunc = sha1.New
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	}

	mac := hmac.New(hashFunc, key)
	mac.Write(msg)
	result := mac.Sum(nil)
	return result
}

func Pbkdf2Hmac(hashName string, password, salt []byte, iterations int) []byte {
	var hashFunc func() hash.Hash
	switch strings.ToLower(hashName) {
	case "sha1":
		hashFunc = sha1.New
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	}
	result := pbkdf2.Key(password, salt, iterations, 50, hashFunc)[:32]
	return result
}

// Internal function used to compute HMACs of DPAPI structures.
func DPAPIHmac(hashName string, pwdhash, hmacSalt, value []byte) []byte {
	encKey := Hmac(pwdhash, hmacSalt, hashName)
	rv := Hmac(encKey, value, hashName)
	return rv
}
