package cngblob

import (
	"github.com/wat4r/dpapitk/utils/asn1"
)

type CngDataBlob struct {
	DpapiBlob, WrapKey, Nonce, Salt, CipherText, EncData []byte
}

func printPacket(packet *asn1.Packet, cngDataBlob *CngDataBlob, count *int) {
	// DpapiBlob
	if *count == 10 {
		cngDataBlob.DpapiBlob = packet.Data.Bytes()
		if len(cngDataBlob.DpapiBlob) > 94 {
			cngDataBlob.Salt = cngDataBlob.DpapiBlob[62:94]
		}
		if len(cngDataBlob.DpapiBlob) > 194 {
			cngDataBlob.CipherText = cngDataBlob.DpapiBlob[146:194]
		}
	}

	// WrapKey
	if *count == 22 {
		cngDataBlob.WrapKey = packet.Data.Bytes()
	}

	// Nonce
	if *count == 28 {
		cngDataBlob.Nonce = packet.Data.Bytes()
	}

	// EncData
	if *count == 30 {
		cngDataBlob.EncData = packet.Data.Bytes()
	}
	*count += 1
	for _, children := range packet.Children {
		printPacket(children, cngDataBlob, count)
	}
}

func parseCngDataBlob(blobData []byte) CngDataBlob {
	var cngDataBlob CngDataBlob
	var count = 1
	data := asn1.DecodePacket(blobData)
	printPacket(data, &cngDataBlob, &count)
	return cngDataBlob
}
