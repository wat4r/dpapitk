package masterkey

import "github.com/wat4r/dpapitk/gocrypto"

// DecryptWithHash Decrypts the backupKey with the given user's hash and SID.
func (backupKey *BackupKey) DecryptWithHash(userSID string, pwdHash []byte) {
	(*MasterKey)(backupKey).DecryptWithKey(gocrypto.DerivePwdHash(pwdHash, userSID, ""))
}
