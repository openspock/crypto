// Package hashes has utility functions to compute hashes of various kind
package hashes

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "errors"
)

// CalculateHmacSha256 calculates a base64 encoded SHA256 HMAC hash and
// returns it, if successful.
func CalculateHmacSha256(msg, secret []byte) ([]byte, error) {
    if secret == nil {
        return nil, errors.New("secret cannot be nil")
    }
    hash := hmac.New(sha256.New, secret)
    hash.Write(msg)
    return []byte (base64.StdEncoding.EncodeToString(hash.Sum(nil))), nil
}
