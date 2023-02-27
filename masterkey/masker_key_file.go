package masterkey

import (
	"github.com/wat4r/dpapitk/gocrypto"
	"github.com/wat4r/dpapitk/hashlib"
	"github.com/wat4r/dpapitk/utils"
)

// InitMasterKeyFile Init master key file.
func InitMasterKeyFile(masterKeyFileData []byte) MasterKeyFile {
	var masterKeyFile = parseMasterKeyFileData(masterKeyFileData)
	masterKeyFile.Decrypted = false
	masterKeyFile.MasterKey.Decrypted = false
	masterKeyFile.BackupKey.Decrypted = false
	masterKeyFile.DomainKey.Decrypted = false
	return masterKeyFile
}

// DecryptWithPassword Decrypt master key file with user password.
func (masterKeyFile *MasterKeyFile) DecryptWithPassword(userSID, password string) {
	pwdEncode := utils.Utf16LfEncode(password)

	// domain1607+ or domain
	sidEncode := utils.Utf16LfEncode(userSID)
	ntlmHash := hashlib.New("md4", pwdEncode)
	derived := hashlib.Pbkdf2(ntlmHash, sidEncode, 32, 10000, "sha256")
	derived = hashlib.Pbkdf2(derived, sidEncode, 16, 1, "sha256")
	masterKeyFile.decryptWithHash(userSID, derived)
	if masterKeyFile.Decrypted {
		return
	}

	// local
	masterKeyFile.decryptWithHash(userSID, hashlib.New("sha1", pwdEncode))
	if masterKeyFile.Decrypted {
		return
	}

	// domain1607- or domain
	masterKeyFile.decryptWithHash(userSID, hashlib.New("md4", pwdEncode))
	if masterKeyFile.Decrypted {
		return
	}
}

// DecryptWithHash Decrypt master key file with ntlm hash or sha1 hash.
func (masterKeyFile *MasterKeyFile) DecryptWithHash(userSID string, hash string) {
	masterKeyFile.decryptWithHash(userSID, utils.HexToBytes(hash))
}

// DecryptWithPvk Decrypt master key file with domain backup key.
func (masterKeyFile *MasterKeyFile) DecryptWithPvk(pvkFileData []byte) {
	masterKeyFile.DomainKey.decryptWithPvk(pvkFileData)
	masterKeyFile.Decrypted = masterKeyFile.DomainKey.Decrypted
	if masterKeyFile.Decrypted {
		masterKeyFile.Key = masterKeyFile.DomainKey.Key
	}
}

// Decrypt master key file with password hash.
func (masterKeyFile *MasterKeyFile) decryptWithHash(userSID string, pwdHash []byte) {
	masterKey := &masterKeyFile.MasterKey
	backupKey := &masterKeyFile.BackupKey

	gocrypto.InitCryptoAlgo()

	if !masterKey.Decrypted {
		masterKey.DecryptWithHash(userSID, pwdHash)
		if !masterKey.Decrypted {
			sidEncode := utils.Utf16LfEncode(userSID)
			derived := hashlib.Pbkdf2(pwdHash, sidEncode, 32, 10000, "sha256")
			derived = hashlib.Pbkdf2(derived, sidEncode, 16, 1, "sha256")
			masterKey.DecryptWithHash(userSID, derived)
		}
	}

	if !backupKey.Decrypted {
		backupKey.DecryptWithHash(userSID, pwdHash)
	}

	masterKeyFile.Decrypted = masterKey.Decrypted || backupKey.Decrypted
	if masterKeyFile.Decrypted {
		masterKeyFile.Key = masterKey.Key
	}
}
