// Derived from: https://medium.com/@bobgzm/golang-cryptography-rsa-asymmetric-algorithm-e91363a2f7b3

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {

	alicePrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	alicePublicKey := &alicePrivateKey.PublicKey

	// trudyPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }
	//trudyPublicKey := &trudyPrivateKey.PublicKey

	bobPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bobPublicKey := &bobPrivateKey.PublicKey

	fmt.Println("Alice's Private Key : ", alicePrivateKey)
	fmt.Println()
	fmt.Println("Alice's Public key ", alicePublicKey)
	fmt.Println()
	fmt.Println("Bob's Private Key : ", bobPrivateKey)
	fmt.Println()
	fmt.Println("Bob's Public key ", bobPublicKey)
	fmt.Println()

	message := []byte("first rule of cs5970 is that you tell everyone about cs5970")
	label := []byte("")
	hash := sha256.New()

	// RSA encryption examples
	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		bobPublicKey,
		message,
		label)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// OAEP is a padding scheme, used with RSA
	fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext)
	fmt.Println()

	// Same encryption, but ciphertext2 will be different due to rand.Reader
	ciphertext2, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		bobPublicKey,
		message,
		label)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// OAEP is a padding scheme, used with RSA
	fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext2)
	fmt.Println()

	// Digital signature examples
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)

	hashed := pssh.Sum(nil)
	signature, err := rsa.SignPSS(
		rand.Reader,
		alicePrivateKey,
		newhash,
		hashed,
		&opts)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Probabilistic Signature Scheme (PSS)
	fmt.Printf("PSS Signature : %x\n", signature)
	fmt.Println()

	plainText, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		bobPrivateKey,
		ciphertext,
		label)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)
	fmt.Println()

	err = rsa.VerifyPSS(
		alicePublicKey,
		newhash,
		hashed,
		signature,
		&opts)

	if err != nil {
		fmt.Println("Signature verification failed!")
		os.Exit(1)
	} else {
		fmt.Println("Signature verification successful!")
	}
}
