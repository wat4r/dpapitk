package masterkey

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"math/big"

	"github.com/wat4r/dpapitk/utils"
)

type PvkFile struct {
	Header         PvkHeader
	PrivateKeyBlob PrivateKeyBlob
}

type PvkHeader struct {
	Magic      uint32
	Reserved   uint32
	KeyType    uint32
	Encrypted  uint32
	SaltLength uint32
	KeyLength  uint32
	Salt       []byte
}

type PrivateKeyBlob struct {
	PublicKeyStruct PublicKeyStruc
	RsaPubKey       RsaPubKey
	Modulus         []byte
	Prime1          []byte
	Prime2          []byte
	Exponent1       []byte
	Exponent2       []byte
	Coefficient     []byte
	PrivateExponent []byte
}

type PublicKeyStruc struct {
	BType    byte
	BVersion byte
	Reserved uint16
	AiKeyAlg uint32
}

type RsaPubKey struct {
	Magic  uint32
	BitLen uint32
	PubExp uint32
}

// Parse domain backup key .pvk file.
func parsePvkFile(pvkFileData []byte) PvkFile {
	var pvkFile = PvkFile{}
	reader := bytes.NewReader(pvkFileData)

	// Read header
	header := &pvkFile.Header
	binary.Read(reader, binary.LittleEndian, &header.Magic)
	binary.Read(reader, binary.LittleEndian, &header.Reserved)
	binary.Read(reader, binary.LittleEndian, &header.KeyType)
	binary.Read(reader, binary.LittleEndian, &header.Encrypted)
	binary.Read(reader, binary.LittleEndian, &header.SaltLength)
	binary.Read(reader, binary.LittleEndian, &header.KeyLength)
	if header.SaltLength > 0 {
		header.Salt = make([]byte, header.SaltLength)
		binary.Read(reader, binary.LittleEndian, &header.Salt)
	}

	// Read PrivateKeyBlob
	privateKeyBlob := &pvkFile.PrivateKeyBlob

	// Read PublicKeyStruc
	publicKeyStruc := &privateKeyBlob.PublicKeyStruct
	binary.Read(reader, binary.LittleEndian, &publicKeyStruc.BType)
	binary.Read(reader, binary.LittleEndian, &publicKeyStruc.BVersion)
	binary.Read(reader, binary.LittleEndian, &publicKeyStruc.Reserved)
	binary.Read(reader, binary.LittleEndian, &publicKeyStruc.AiKeyAlg)

	// Read RsaPubKey
	rsaPubKey := &privateKeyBlob.RsaPubKey
	binary.Read(reader, binary.LittleEndian, &rsaPubKey.Magic)
	binary.Read(reader, binary.LittleEndian, &rsaPubKey.BitLen)
	binary.Read(reader, binary.LittleEndian, &rsaPubKey.PubExp)

	privateKeyBlob.Modulus = make([]byte, rsaPubKey.BitLen/8)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Modulus)

	privateKeyBlob.Prime1 = make([]byte, rsaPubKey.BitLen/16)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Prime1)

	privateKeyBlob.Prime2 = make([]byte, rsaPubKey.BitLen/16)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Prime2)

	privateKeyBlob.Exponent1 = make([]byte, rsaPubKey.BitLen/16)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Exponent1)

	privateKeyBlob.Exponent2 = make([]byte, rsaPubKey.BitLen/16)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Exponent2)

	privateKeyBlob.Coefficient = make([]byte, rsaPubKey.BitLen/16)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.Coefficient)

	privateKeyBlob.PrivateExponent = make([]byte, rsaPubKey.BitLen/8)
	binary.Read(reader, binary.LittleEndian, &privateKeyBlob.PrivateExponent)
	return pvkFile
}

// Parse private key into pkcs#1 format.
func pvkToPkcs1(pvkFile PvkFile) rsa.PrivateKey {
	key := pvkFile.PrivateKeyBlob

	modulus := big.NewInt(0).SetBytes(utils.ReverseBytes(key.Modulus))            // n
	prime1 := big.NewInt(0).SetBytes(utils.ReverseBytes(key.Prime1))              // p
	prime2 := big.NewInt(0).SetBytes(utils.ReverseBytes(key.Prime2))              // q
	privateExp := big.NewInt(0).SetBytes(utils.ReverseBytes(key.PrivateExponent)) // d
	pubExp := int(key.RsaPubKey.PubExp)                                           // e

	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: modulus,
			E: pubExp,
		},
		D:      privateExp,
		Primes: []*big.Int{prime1, prime2},
	}
	privateKey.Precompute()
	privateKey.Validate()
	return privateKey
}
