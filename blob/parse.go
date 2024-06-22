package blob

import (
	"bytes"
	"encoding/binary"
)

type DataBlob struct {
	Version          uint32
	GuidProvider     [16]byte
	MasterKeyVersion uint32
	GuidMasterKey    [16]byte
	Flags            uint32
	DescriptionLen   uint32
	Description      []byte
	AlgCrypt         uint32
	AlgCryptLen      uint32
	SaltLen          uint32
	Salt             []byte
	HmacKeyLen       uint32
	HmacKey          []byte
	AlgHash          uint32
	AlgHashLen       uint32
	Hmac2KeyLen      uint32
	Hmack2Key        []byte
	DataLen          uint32
	Data             []byte
	ToSign           []byte // add
	SignLen          uint32
	Sign             []byte
}

func ParseDataBlob(blobData []byte) DataBlob {
	var dataBlob = DataBlob{}
	reader := bytes.NewReader(blobData)

	binary.Read(reader, binary.LittleEndian, &dataBlob.Version)
	binary.Read(reader, binary.LittleEndian, &dataBlob.GuidProvider)
	binary.Read(reader, binary.LittleEndian, &dataBlob.MasterKeyVersion)
	binary.Read(reader, binary.LittleEndian, &dataBlob.GuidMasterKey)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Flags)
	binary.Read(reader, binary.LittleEndian, &dataBlob.DescriptionLen)
	dataBlob.Description = make([]byte, dataBlob.DescriptionLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Description)
	binary.Read(reader, binary.LittleEndian, &dataBlob.AlgCrypt)
	binary.Read(reader, binary.LittleEndian, &dataBlob.AlgCryptLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.SaltLen)
	dataBlob.Salt = make([]byte, dataBlob.SaltLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Salt)

	binary.Read(reader, binary.LittleEndian, &dataBlob.HmacKeyLen)
	dataBlob.HmacKey = make([]byte, dataBlob.HmacKeyLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.HmacKey)

	binary.Read(reader, binary.LittleEndian, &dataBlob.AlgHash)
	binary.Read(reader, binary.LittleEndian, &dataBlob.AlgHashLen)

	binary.Read(reader, binary.LittleEndian, &dataBlob.Hmac2KeyLen)
	dataBlob.Hmack2Key = make([]byte, dataBlob.Hmac2KeyLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Hmack2Key)

	binary.Read(reader, binary.LittleEndian, &dataBlob.DataLen)
	dataBlob.Data = make([]byte, dataBlob.DataLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Data)

	toSignLen := 60 + dataBlob.DescriptionLen + dataBlob.SaltLen + dataBlob.HmacKeyLen + dataBlob.Hmac2KeyLen + dataBlob.DataLen
	dataBlob.ToSign = make([]byte, toSignLen)
	binary.Read(bytes.NewReader(blobData[20:]), binary.LittleEndian, &dataBlob.ToSign)

	binary.Read(reader, binary.LittleEndian, &dataBlob.SignLen)
	dataBlob.Sign = make([]byte, dataBlob.SignLen)
	binary.Read(reader, binary.LittleEndian, &dataBlob.Sign)

	return dataBlob
}
