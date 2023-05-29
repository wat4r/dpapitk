package cngblob

import (
	"github.com/wat4r/dpapitk/blob"
	"github.com/wat4r/dpapitk/gocrypto"
)

// DecryptWithMasterKey Decrypt CNG DPAPI blob data with master key.
func DecryptWithMasterKey(blobData, masterKey, entropy []byte) ([]byte, error) {
	var cngDataBlob CngDataBlob
	cngDataBlob = parseCngDataBlob(blobData)

	bigKEK, err := blob.DecryptWithMasterKey(cngDataBlob.DpapiBlob, masterKey, entropy)
	if err != nil {
		return nil, err
	}
	bigWrapped := cngDataBlob.WrapKey
	bigKey := gocrypto.AesUnwrapKey(bigKEK, bigWrapped)
	bigIv := cngDataBlob.Nonce

	plainText, err := gocrypto.AesGcmDecrypt(bigKey, cngDataBlob.EncData, bigIv)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
