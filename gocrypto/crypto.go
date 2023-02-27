package gocrypto

import (
	"github.com/wat4r/dpapitk/hashlib"
	"github.com/wat4r/dpapitk/utils"
)

// Internal use. Computes the encryption key from a user's password hash.
func DerivePwdHash(pwdHash []byte, userSID string, digest string) []byte {
	if digest == "" {
		digest = "sha1"
	}
	return hashlib.Hmac(pwdHash, utils.Utf16LfEncode(userSID+string([]byte{0x00})), digest)
}

// Internal use. Decrypts data stored in DPAPI structures.
func DataDecrypt(cipherAlgo CryptoAlgo, hashName string, raw, encKey, iv []byte, rounds int) []byte {
	derived := hashlib.Pbkdf2Ms(encKey, iv, cipherAlgo.KeyLength+cipherAlgo.IvLength, rounds, hashName)
	key, iv := derived[:cipherAlgo.KeyLength], derived[cipherAlgo.KeyLength:]
	key = key[:cipherAlgo.KeyLength]
	iv = iv[:cipherAlgo.IvLength]
	clearTxt := ModuleDecrypt(raw, key, cipherAlgo.Module, "CBC", iv)
	return clearTxt
}
