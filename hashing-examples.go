package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
)

func main() {
	s := "hello"

	sha256 := sha256.Sum256([]byte(s))
	md5 := md5.Sum([]byte(s))

	fmt.Println()
	fmt.Println(s)

	fmt.Println()
	fmt.Printf("%x", sha256)
	fmt.Println()

	fmt.Println()
	fmt.Printf("%x", md5)

	fmt.Println()
	fmt.Println()

}
