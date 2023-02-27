package masterkey

import (
	"bytes"
	"encoding/binary"
)

type MasterKeyFile struct {
	Header    Header
	MasterKey MasterKey
	BackupKey BackupKey
	CredHist  CredHist
	DomainKey DomainKey
	Decrypted bool
	Guid      []byte
	Key       []byte
}

type Header struct {
	Version      uint32
	Guid         []byte
	Policy       uint32
	MasterKeyLen uint64
	BackupKeyLen uint64
	CredHistLen  uint64
	DomainKeyLen uint64
}

type MasterKey struct {
	Version  uint32
	Salt     [16]byte
	Rounds   uint32
	AlgHash  uint32
	AlgCrypt uint32
	PbKey    []byte

	// Store result data
	Decrypted    bool
	Key          []byte
	KeyHash      []byte
	HmacSalt     []byte
	Hmac         []byte
	HmacComputed []byte
}

type BackupKey MasterKey

type CredHist struct {
	Version uint32
	Guid    [16]byte
}

type DomainKey struct {
	Version         uint32
	SecretLen       uint32
	AccessCheckLen  uint32
	GuidKey         []byte
	EncryptedSecret []byte
	AccessCheck     []byte

	// Store result data
	Decrypted bool
	Key       []byte
}

// Read DPAPI master key file into structure.
func parseMasterKeyFileData(blobData []byte) MasterKeyFile {
	var skip = 0
	var masterKeyFile MasterKeyFile

	// Parse header
	masterKeyFile.Header = readHeader(blobData)
	skip += 128

	// Parse masterKey
	masterKeyLen := int(masterKeyFile.Header.MasterKeyLen)
	if masterKeyLen > 0 {
		masterKeyFile.MasterKey = readMasterKey(blobData[skip:], masterKeyLen)
		skip += masterKeyLen
	}

	// Parse masterKey
	backupKeyLen := int(masterKeyFile.Header.BackupKeyLen)
	if backupKeyLen > 0 {
		masterKeyFile.BackupKey = readBackupKey(blobData[skip:], backupKeyLen)
		skip += backupKeyLen
	}

	// Parse credHistLen
	credHistLen := int(masterKeyFile.Header.CredHistLen)
	if credHistLen > 0 {
		masterKeyFile.CredHist = readCredHist(blobData[skip:], credHistLen)
		skip += credHistLen
	}

	// Parse domainKey
	domainKeyLen := int(masterKeyFile.Header.DomainKeyLen)
	if domainKeyLen > 0 {
		masterKeyFile.DomainKey = readDomainKey(blobData[skip:], domainKeyLen)
		skip += domainKeyLen
	}

	return masterKeyFile
}

func readHeader(data []byte) Header {
	var header Header
	reader := bytes.NewReader(data)
	var Q uint64

	binary.Read(reader, binary.LittleEndian, &header.Version)
	binary.Read(reader, binary.LittleEndian, &Q)
	header.Guid = make([]byte, 72)
	binary.Read(reader, binary.LittleEndian, &header.Guid)
	binary.Read(reader, binary.LittleEndian, &Q)
	binary.Read(reader, binary.LittleEndian, &header.Policy)
	binary.Read(reader, binary.LittleEndian, &header.MasterKeyLen)
	binary.Read(reader, binary.LittleEndian, &header.BackupKeyLen)
	binary.Read(reader, binary.LittleEndian, &header.CredHistLen)
	binary.Read(reader, binary.LittleEndian, &header.DomainKeyLen)
	return header
}

func readMasterKey(data []byte, masterKeyLen int) MasterKey {
	var masterKey MasterKey
	reader := bytes.NewReader(data)

	binary.Read(reader, binary.LittleEndian, &masterKey.Version)
	binary.Read(reader, binary.LittleEndian, &masterKey.Salt)
	binary.Read(reader, binary.LittleEndian, &masterKey.Rounds)
	binary.Read(reader, binary.LittleEndian, &masterKey.AlgHash)
	binary.Read(reader, binary.LittleEndian, &masterKey.AlgCrypt)

	masterKey.PbKey = make([]byte, masterKeyLen-32)
	binary.Read(reader, binary.LittleEndian, &masterKey.PbKey)
	return masterKey
}

func readBackupKey(data []byte, backupKeyLen int) BackupKey {
	var backupKey BackupKey
	reader := bytes.NewReader(data)

	binary.Read(reader, binary.LittleEndian, &backupKey.Version)
	binary.Read(reader, binary.LittleEndian, &backupKey.Salt)
	binary.Read(reader, binary.LittleEndian, &backupKey.Rounds)
	binary.Read(reader, binary.LittleEndian, &backupKey.AlgHash)
	binary.Read(reader, binary.LittleEndian, &backupKey.AlgCrypt)

	backupKey.PbKey = make([]byte, backupKeyLen-32)
	binary.Read(reader, binary.LittleEndian, &backupKey.PbKey)
	return backupKey
}

func readCredHist(data []byte, backupKeyLen int) CredHist {
	var credHist CredHist
	reader := bytes.NewReader(data)

	binary.Read(reader, binary.LittleEndian, &credHist.Version)
	binary.Read(reader, binary.LittleEndian, &credHist.Guid)
	return credHist
}

func readDomainKey(data []byte, domainKeyLen int) DomainKey {
	var domainKey DomainKey
	reader := bytes.NewReader(data)

	binary.Read(reader, binary.LittleEndian, &domainKey.Version)
	binary.Read(reader, binary.LittleEndian, &domainKey.SecretLen)
	binary.Read(reader, binary.LittleEndian, &domainKey.AccessCheckLen)

	domainKey.GuidKey = make([]byte, 16)
	binary.Read(reader, binary.LittleEndian, &domainKey.GuidKey)

	domainKey.EncryptedSecret = make([]byte, domainKey.SecretLen)
	binary.Read(reader, binary.LittleEndian, &domainKey.EncryptedSecret)

	domainKey.AccessCheck = make([]byte, domainKey.AccessCheckLen)
	binary.Read(reader, binary.LittleEndian, &domainKey.AccessCheck)
	return domainKey
}
