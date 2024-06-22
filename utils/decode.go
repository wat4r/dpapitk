package utils

import "fmt"

func GuidMasterKeyConvert(guidMasterKey [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		ReverseBytes(guidMasterKey[:4]),
		ReverseBytes(guidMasterKey[4:6]),
		ReverseBytes(guidMasterKey[6:8]),
		guidMasterKey[8:10],
		guidMasterKey[10:])
}
