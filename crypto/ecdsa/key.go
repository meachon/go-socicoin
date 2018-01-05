package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

const (
	BigNubLength  = 32
	PrivKeyLength = 32
	PubKeyLength  = 64
	SigLength     = 64
)

type PrivKey [PrivKeyLength]byte
type PubKey [PubKeyLength]byte

func GenerateKey() (*PrivKey, error) {
	var prvk = new(PrivKey)

	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	copy(prvk[:], prk.D.Bytes())
	return prvk, nil
}

func GetPublicKey(prvk *PrivKey) (*PubKey, error) {
	var (
		pubk = new(PubKey)
		x, y *big.Int
	)

	x, y = elliptic.P256().ScalarBaseMult(prvk[:])
	copy(pubk[:BigNubLength], x.Bytes())
	copy(pubk[BigNubLength:], y.Bytes())
	return pubk, nil
}
