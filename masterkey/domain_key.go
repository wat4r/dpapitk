package masterkey

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"

	"github.com/wat4r/dpapitk/utils"
)

type DpapiDomainRsaMasterKey struct {
	CbMasterKey uint32
	CbSuppKey   uint32
	Buffer      []byte
}

func (domainKey *DomainKey) decryptWithPvk(pvkFileData []byte) {
	pvkFile := parsePvkFile(pvkFileData)
	privateKey := pvkToPkcs1(pvkFile)

	ciphertext := utils.ReverseBytes(domainKey.EncryptedSecret)
	decryptedKey, err := rsa.DecryptPKCS1v15(nil, &privateKey, ciphertext)
	if err != nil {
		return
	}
	domainMasterKey := parseDomainRsaMasterKey(decryptedKey)
	if len(domainMasterKey.Buffer) > 0 {
		domainKey.Key = domainMasterKey.Buffer[:domainMasterKey.CbMasterKey]
		domainKey.Decrypted = true
	}
}

func parseDomainRsaMasterKey(decryptedKey []byte) DpapiDomainRsaMasterKey {
	var dpapiDomainRsaMasterKey = DpapiDomainRsaMasterKey{}

	reader := bytes.NewReader(decryptedKey)
	binary.Read(reader, binary.LittleEndian, &dpapiDomainRsaMasterKey.CbMasterKey)
	binary.Read(reader, binary.LittleEndian, &dpapiDomainRsaMasterKey.CbSuppKey)
	dpapiDomainRsaMasterKey.Buffer = make([]byte, len(decryptedKey)-8)
	binary.Read(reader, binary.LittleEndian, &dpapiDomainRsaMasterKey.Buffer)
	return dpapiDomainRsaMasterKey
}
