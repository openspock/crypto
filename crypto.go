// Package crypto contains custom functions to encrpyt and decrypt
// messages based on a user's secret
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypt encrypts a plain text message using AES in GCM mode and a secret hash and
// returns the encrypted message, if successful.
func Encrypt(msg, secret []byte) ([]byte, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, msg, nil), nil
}

// Decrypt decrypts an encrypted message using AES in GCM mode and 'the' secret hash
// which was used to encrypt the message. It returns the decrypted plain text
// message, if successful.
func Decrypt(encryptedMsg, secret []byte) ([]byte, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedMsg) < nonceSize {
		return nil, errors.New("encrypted message too short")
	}
	nonce, encryptedMsg := encryptedMsg[:nonceSize], encryptedMsg[nonceSize:]
	return gcm.Open(nil, nonce, encryptedMsg, nil)
}
