package utils

import "os"

func ReadFile(filepath string) []byte {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil
	}
	return data
}

func WriteFile(filePath string, content []byte) bool {
	err := os.WriteFile(filePath, content, 0644)
	return err == nil
}
