package gocrypto

var CryptoData = make(map[int]CryptoAlgo)

type CryptoAlgo struct {
	Name         string
	Module       string
	KeyLength    int
	IvLength     int
	BlockSize    int
	DigestLength int
}

func init() {
	addAlgo1(0x6603, "3DES", 192, 64, 64, "3DES")
	addAlgo1(0x6611, "AES", 128, 128, 128, "AES")
	addAlgo1(0x660e, "AES-128", 128, 128, 128, "AES")
	addAlgo1(0x660f, "AES-192", 192, 128, 128, "AES")
	addAlgo1(0x6610, "AES-256", 256, 128, 128, "AES")

	addAlgo2(0x8009, "HMAC", 160, 512)
	addAlgo2(0x8003, "md5", 128, 512)
	addAlgo2(0x8004, "sha1", 160, 512)
	addAlgo2(0x800c, "sha256", 256, 512)
	addAlgo2(0x800d, "sha384", 384, 1024)
	addAlgo2(0x800e, "sha512", 512, 1024)
}

func InitCryptoAlgo() map[int]CryptoAlgo {
	addAlgo1(0x6603, "3DES", 192, 64, 64, "3DES")
	addAlgo1(0x6611, "AES", 128, 128, 128, "AES")
	addAlgo1(0x660e, "AES-128", 128, 128, 128, "AES")
	addAlgo1(0x660f, "AES-192", 192, 128, 128, "AES")
	addAlgo1(0x6610, "AES-256", 256, 128, 128, "AES")

	addAlgo2(0x8009, "HMAC", 160, 512)
	addAlgo2(0x8003, "md5", 128, 512)
	addAlgo2(0x8004, "sha1", 160, 512)
	addAlgo2(0x800c, "sha256", 256, 512)
	addAlgo2(0x800d, "sha384", 384, 1024)
	addAlgo2(0x800e, "sha512", 512, 1024)

	return CryptoData
}

func GetAlgo(algNum int) CryptoAlgo {
	return CryptoData[algNum]
}

func addAlgo1(algNum int, name string, keyLength, ivLength, blockSize int, module string) {
	CryptoData[algNum] = CryptoAlgo{
		Name:      name,
		Module:    module,
		KeyLength: keyLength / 8,
		IvLength:  ivLength / 8,
		BlockSize: blockSize / 8,
	}
}

func addAlgo2(algNum int, name string, digestLength, blockSize int) {
	CryptoData[algNum] = CryptoAlgo{
		Name:         name,
		BlockSize:    blockSize / 8,
		DigestLength: digestLength / 8,
	}
}
