package masterkey

import (
	"bytes"

	"github.com/wat4r/dpapitk/gocrypto"
	"github.com/wat4r/dpapitk/hashlib"
)

// Decrypts the masterKey with the given user's hash and SID.
func (masterKey *MasterKey) DecryptWithHash(userSID string, pwdHash []byte) {
	masterKey.DecryptWithKey(gocrypto.DerivePwdHash(pwdHash, userSID, ""))
}

/*
	 Decrypts the masterKey with the given encryption key. This function
		also extracts the HMAC part of the decrypted stuff and compare it with
		the computed one.
		Note that, once successfully decrypted, the masterKey will not be
		decrypted anymore; this function will simply return.
*/
func (masterKey *MasterKey) DecryptWithKey(pwdHash []byte) {
	if masterKey.Decrypted || len(masterKey.PbKey) == 0 {
		return
	}

	cipherAlgo := gocrypto.GetAlgo(int(masterKey.AlgCrypt))
	hashAlgo := gocrypto.GetAlgo(int(masterKey.AlgHash))
	hashName := map[string]string{
		"HMAC": "sha1",
	}[hashAlgo.Name]
	if hashName == "" {
		hashName = hashAlgo.Name
	}
	clearTxt := gocrypto.DataDecrypt(cipherAlgo, hashName, masterKey.PbKey, pwdHash, masterKey.Salt[:], int(masterKey.Rounds))

	masterKey.Key = clearTxt[len(clearTxt)-64:]
	masterKey.HmacSalt = clearTxt[:16]
	masterKey.Hmac = clearTxt[16 : 16+hashAlgo.DigestLength]
	masterKey.HmacComputed = hashlib.DPAPIHmac(hashName, pwdHash, masterKey.HmacSalt, masterKey.Key)

	if bytes.Equal(masterKey.Hmac, masterKey.HmacComputed) {
		masterKey.Decrypted = true
	} else {
		masterKey.Decrypted = false
	}
}
