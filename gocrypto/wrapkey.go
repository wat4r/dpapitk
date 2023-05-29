package gocrypto

import (
	"crypto/aes"
	"encoding/binary"
)

func AesUnwrapKey(key, cipherText []byte) []byte {
	if len(cipherText)%8 != 0 {
		return nil
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	unblocks := len(cipherText)/8 - 1

	// 1) Initialize variables.
	var block [aes.BlockSize]byte
	// - Set A = C[0]
	copy(block[:8], cipherText[:8])

	// - For i = 1 to n
	// -   Set R[i] = C[i]
	intermediate := make([]byte, len(cipherText)-8)
	copy(intermediate, cipherText[8:])

	// 2) Compute intermediate values.
	for jj := 5; jj >= 0; jj-- {
		for ii := unblocks - 1; ii >= 0; ii-- {
			// - B = AES-1(K, (A ^ t) | R[i]) where t = n*j+1
			// - A = MSB(64, B)
			t := uint64(jj*unblocks + ii + 1)
			val := binary.BigEndian.Uint64(block[:8]) ^ t
			binary.BigEndian.PutUint64(block[:8], val)

			copy(block[8:], intermediate[ii*8:ii*8+8])
			c.Decrypt(block[:], block[:])

			// - R[i] = LSB(B, 64)
			copy(intermediate[ii*8:ii*8+8], block[8:])
		}
	}

	// 3) Output results.
	// - If A is an appropriate initial value (see 2.2.3),
	for ii := 0; ii < 8; ii++ {
		if block[ii] != 0xA6 {
			return nil
		}
	}

	// - For i = 1 to n
	// -   P[i] = R[i]
	return intermediate
}
