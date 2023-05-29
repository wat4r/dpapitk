# DPAPI Toolkit
[![Test](https://github.com/wat4r/dpapitk/workflows/Test/badge.svg)](https://github.com/wat4r/dpapitk/actions)
[![GoDoc](https://pkg.go.dev/badge/github.com/wat4r/dpapitk)](https://pkg.go.dev/github.com/wat4r/dpapitk)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


## Introduction
DPAPI Toolkit is a DPAPI(Data Protection API) and DPAPI-NG(Data Protection API Next Generation) decryption toolkit based on Golang, providing APIs for offline data decryption on different operating systems. It supports decryption methods such as password, hash, and domain backup key.


## Install
```bash
go get github.com/wat4r/dpapitk
```


## Usage and example
### Decrypt master key file
```go
package main

import (
    "fmt"
    "github.com/wat4r/dpapitk/utils"
    "github.com/wat4r/dpapitk/masterkey"
)

func main()  {
	data := utils.ReadFile("./ea80d547-868c-4fc3-83cf-07203330d3be")
	masterKeyFile := masterkey.InitMasterKeyFile(data)
	sid := "S-1-5-21-3461634040-4115545689-1944680405-500"
	
	password := "123456"
	masterKeyFile.DecryptWithPassword(sid, password)
	
	// hash := "aa647b916a1fad374df9c30711d58a7a"
	// masterKeyFile.DecryptWithHash(sid, hash)

	// pvkFileData := dpapitk.utils.ReadFile("./domain_backup_key.pvk")
	// masterKeyFile.DecryptWithPvk(pvkFileData)
	
	fmt.Printf("Status: %v, Master key: %x\n", masterKeyFile.Decrypted, masterKeyFile.Key)
}
```


### Decrypt DPAPI data blob
```go
package main

import (
	"fmt"
	"github.com/wat4r/dpapitk/blob"
)

func main()  {
	blobData := []byte{...}
	masterKey := []byte{...}
	entropy := nil
	
	data, err := blob.DecryptWithMasterKey(blobData, masterKey, entropy)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Data: %x\n", data)
}
```


### Decrypt CNG DPAPI data blob
```go
package main

import (
	"fmt"
	"github.com/wat4r/dpapitk/cngblob"
)

func main()  {
	blobData := []byte{...}
	masterKey := []byte{...}
	entropy := nil
	
	data, err := cngblob.DecryptWithMasterKey(blobData, masterKey, entropy)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Data: %x\n", data)
}
```


## TODO
 ✔️ ~~DPAPI-NG(CNG DPAPI) data blob decrypt~~


## License
This project is licensed under the [Apache 2.0 license](LICENSE).



## Contact
If you have any issues or feature requests, please contact us. PR is welcomed.
 - https://github.com/wat4r/dpapitk/issues

