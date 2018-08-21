package crypto

import (
	"fmt"
	"log"
	"testing"
)

func TestEncryption(t *testing.T) {
	test := []byte("This is a test message")
	secret := []byte("The-key-has-to-be-32-bytes-long!")

	encryptedMsg, err := Encrypt(test, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted message: %q\n", encryptedMsg)

	decryptedMsg, err := Decrypt(encryptedMsg, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted message: %q \n", decryptedMsg)
}

func TestEncryptionInvalidKeyLen(t *testing.T) {
	test := []byte("This is a test message")
	secret := []byte("The-key-has-to-long!")

	_, err := Encrypt(test, secret)
	if err != nil {
		log.Println(err)
	} else {
		t.Fail()
	}
}

func TestDecryptionInvalidKeyLen(t *testing.T) {
	test := []byte("This is a test message")
	secret := []byte("The-key-has-to-be-32-bytes-long!")

	encryptedMsg, err := Encrypt(test, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted message: %q\n", encryptedMsg)

	secret = []byte("The-key-has-to-be-long!")
	_, err = Decrypt(encryptedMsg, secret)
	if err != nil {
		log.Println(err)
	} else {
		t.Fail()
	}
}
