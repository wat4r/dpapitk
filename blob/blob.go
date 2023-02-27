package blob

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wat4r/dpapitk/gocrypto"
	"github.com/wat4r/dpapitk/hashlib"
)

// DecryptWithMasterKey Decrypt dpapi blob data with master key.
func DecryptWithMasterKey(blobData []byte, masterKey, entropy []byte) ([]byte, error) {
	if len(blobData) < 60 {
		return nil, errors.New("blobData failed")
	}

	dataBlob := parseDataBlob(blobData)
	if len(dataBlob.Sign) == 0 {
		return nil, errors.New("parsing blob failed")
	}

	keyHash := hashlib.New("sha1", masterKey)
	hashAlgo := gocrypto.GetAlgo(int(dataBlob.AlgHash))
	msg := dataBlob.Salt
	if len(entropy) > 0 {
		msg = append(msg, entropy...)
	}
	sessionKey := hashlib.Hmac(keyHash, msg, hashAlgo.Name)

	var derivedKey []byte
	if len(sessionKey) > hashAlgo.BlockSize {
		derivedKey = hashlib.Hmac(sessionKey, nil, hashAlgo.Name)
	} else {
		derivedKey = sessionKey
	}

	cryptoAlgo := gocrypto.GetAlgo(int(dataBlob.AlgCrypt))
	if len(derivedKey) < cryptoAlgo.KeyLength {
		//	Extend the key
		derivedKey = append(derivedKey, make([]byte, hashAlgo.BlockSize)...)
		ipad := xorArray(0x36, derivedKey)[:hashAlgo.BlockSize]
		opad := xorArray(0x5c, derivedKey)[:hashAlgo.BlockSize]
		derivedKey = append(hashlib.New(hashAlgo.Name, ipad), hashlib.New(hashAlgo.Name, opad)...)
		derivedKey = fixParity(derivedKey)
	}

	key := derivedKey[:cryptoAlgo.KeyLength]
	iv := make([]byte, cryptoAlgo.IvLength)
	clearText := pkcs7UnPad(gocrypto.ModuleDecrypt(dataBlob.Data, key, cryptoAlgo.Module, "CBC", iv), cryptoAlgo.IvLength)

	// Calculate the different HMACKeys
	hashBlockSize := hashAlgo.BlockSize
	keyHash2 := append(keyHash, make([]byte, hashBlockSize)...)
	ipad := xorArray(0x36, keyHash2)[:hashBlockSize]
	opad := xorArray(0x5c, keyHash2)[:hashBlockSize]

	data := hashlib.New(hashAlgo.Name, append(ipad, dataBlob.Hmack2Key...))
	data = append(opad, data...)
	data = append(data, entropy...)
	data = append(data, dataBlob.ToSign...)
	hmacCalculated1 := hashlib.New(hashAlgo.Name, data)

	msg = dataBlob.Hmack2Key
	if len(entropy) > 0 {
		msg = append(msg, entropy...)
	}
	msg = append(msg, dataBlob.ToSign...)
	hmacCalculated3 := hashlib.Hmac(keyHash, msg, hashAlgo.Name)

	if bytes.Equal(hmacCalculated1, dataBlob.Sign) || bytes.Equal(hmacCalculated3, dataBlob.Sign) {
		return clearText, nil
	} else {
		return nil, errors.New("decryption failed")
	}
}

func xorArray(key byte, date []byte) []byte {
	var dataNew []byte
	for _, item := range date {
		dataNew = append(dataNew, item^key)
	}
	return dataNew
}

func fixParity(desKey []byte) []byte {
	var temp []byte
	for i := 0; i < len(desKey); i++ {
		t := fmt.Sprintf("%08b", desKey[i])
		if strings.Count(t[:7], "1")%2 == 0 {
			b, _ := strconv.ParseUint(t[:7]+"1", 2, 8)
			temp = append(temp, byte(b))
		} else {
			b, _ := strconv.ParseUint(t[:7]+"0", 2, 8)
			temp = append(temp, byte(b))
		}
	}
	return temp
}

// Remove the PKCS#7 padding from a text byteString.
func pkcs7UnPad(data []byte, k int) []byte {
	if k <= 0 {
		k = 16
	}

	val := int(data[len(data)-1])
	if val > k {
		return data
	}
	return data[:len(data)-val]
}
