package apocrypha

import (
  "fmt"
  "os"
  "math/rand"
  "time"
)

func XorEncrypt(filepath string) {
	fmt.Println("XOR Encrypting "+filepath+".bin...")
	//Seed rand()
	rand.Seed(time.Now().UnixNano())
	// Generate key
	key := make([]byte, 1)
	rand.Read(key)
	//Write key to file
	key_f, err := os.Create("./output/encrypt.key")
  	if err != nil {
    	panic(err)
  	}
	_, err = key_f.Write(key)
  	if err != nil {
    	panic(err)
  	}
	key_f.Close()
	//Read shellcode file
	shellcode_buf, err := os.ReadFile("./output/"+filepath+".bin")
	if err != nil {
    	panic(err)
  	}
	// XOR encrypt shellcode the rewrite ciphertext to file 
	ciphertext := make([]byte, len(shellcode_buf))
	for i := 0; i < len(shellcode_buf); i++ {
		ciphertext[i] = shellcode_buf[i] ^ key[0]
	}
	overwrite_bin, err := os.Create("./output/"+filepath+".bin")
	if err != nil {
		panic(err)
	}
	_, err = overwrite_bin.Write(ciphertext)
  	if err != nil {
    	panic(err)
  	}
	overwrite_bin.Close()
}