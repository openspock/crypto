package hashes

import (
    "fmt"
    "log"
    "reflect"
    "testing"
)

func TestNilSecretMsg(t *testing.T) {
    secret := []byte("password")
    hash1, err1 := CalculateHmacSha256(nil, secret)
    hash2, err2 := CalculateHmacSha256(nil, secret)
    handleNilHash(hash1, t)
    handleErr(err1)
    handleNilHash(hash2, t)
    handleErr(err2)

    if !reflect.DeepEqual(hash1, hash2) {
        fmt.Println("Nil message should produce same hash consistently")
        t.Fail()
    }
}

func TestConsistency(t *testing.T) {
    msg1, secret1 := []byte("This is a test message"), []byte("password")
    msg2, secret2 := []byte("This is a test message"), []byte("password")
    hash1, err := CalculateHmacSha256(msg1, secret1)
    handleNilHash(hash1, t)
    handleErr(err)
    hash2, err := CalculateHmacSha256(msg2, secret2)
    handleNilHash(hash2, t)
    handleErr(err)
    if !reflect.DeepEqual(hash1, hash2) {
        fmt.Println("Hash value should be consistent across multiple calculation of the same message and secret")
        t.Fail()
    }
}

func TestConsistencyFailure(t *testing.T) {
    msg1, secret1 := []byte("This is a test message"), []byte("password")
    msg2, secret2 := []byte("This is a test message"), []byte("wrong password")
    hash1, err := CalculateHmacSha256(msg1, secret1)
    handleNilHash(hash1, t)
    handleErr(err)
    hash2, err := CalculateHmacSha256(msg2, secret2)
    handleNilHash(hash2, t)
    handleErr(err)
    if reflect.DeepEqual(hash1, hash2) {
        fmt.Println("Different secret should produce different hashes even for the same message")
        t.Fail()
    }
}

func handleErr(e error) {
    if e!= nil {
        log.Fatal(e)
    }
}

func handleNilHash(hash []byte, t *testing.T) {
    if hash == nil {
        fmt.Println("hash cannot be nil")
        t.Fail()
    }
}
