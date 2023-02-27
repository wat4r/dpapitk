package utils

import (
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

func Utf16LfEncode(msg string) (result []byte) {
	runes := utf16.Encode([]rune(msg))
	for _, r := range runes {
		item := []byte{byte(r), 0x00}
		result = append(result, item...)
	}
	return
}

func HexToBytes(hexData string) []byte {
	byteData, _ := hex.DecodeString(hexData)
	return byteData
}

func BytesToHex(bytesData []byte) (result string) {
	for i := 0; i < len(bytesData); i++ {
		result += fmt.Sprintf("%.2x ", bytesData[i])
	}
	if len(result) > 0 {
		result = result[:len(result)-1]
	}
	return
}

func AnyToHex(data any) string {
	return fmt.Sprintf("%.2x ", data)
}

func ReverseBytes(data []byte) []byte {
	for i := 0; i < len(data)/2; i++ {
		j := len(data) - i - 1
		data[i], data[j] = data[j], data[i]
	}
	return data
}
