package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"hash"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func Create(h func() hash.Hash, iters int, passphrase []byte) (result, salt []byte, err error) {
	salt = make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	result = Check(h, iters, passphrase, salt)
	return result, salt, err
}

func CalculateIterations(h func() hash.Hash) (int, error) {
	hashInstance := h()
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return 0, err
	}
	iter := 2048
	var duration time.Duration
	for duration < time.Second {
		iter = iter * 2
		timeStart := time.Now()
		pbkdf2.Key([]byte("password1"), salt, iter, hashInstance.Size(), h)
		duration = time.Since(timeStart)
	}
	return iter, nil
}

func Check(h func() hash.Hash, iters int, passphrase, salt []byte) []byte {
	hashInstance := h()
	return pbkdf2.Key(passphrase, salt, iters, hashInstance.Size(), h)
}

func Compare(candidate, expectation []byte) bool {
	candidateConsistent := make([]byte, len(candidate))
	expectationConsistent := make([]byte, len(candidate))
	subtle.ConstantTimeCopy(1, candidateConsistent, candidate)
	subtle.ConstantTimeCopy(1, expectationConsistent, expectation)
	return subtle.ConstantTimeCompare(candidateConsistent, expectationConsistent) == 1
}
