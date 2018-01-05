package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type ECDSASign [SigLength]byte

func Signature(prvk *PrivKey, hash []byte) (*ECDSASign, error) {
	var (
		prk ecdsa.PrivateKey
		k   big.Int
		sig = new(ECDSASign)
	)

	k.SetBytes(prvk[:])
	prk.D = &k
	prk.PublicKey.Curve = elliptic.P256()
	prk.PublicKey.X, prk.PublicKey.Y = elliptic.P256().ScalarBaseMult(prvk[:])

	r, s, err := ecdsa.Sign(rand.Reader, &prk, hash)
	if err != nil {
		return nil, err
	}
	copy(sig[:BigNubLength], r.Bytes())
	copy(sig[BigNubLength:], s.Bytes())
	return sig, nil
}

func Verify(pubk *PubKey, hash []byte, sig *ECDSASign) bool {
	var (
		pubkey     ecdsa.PublicKey
		x, y, r, s big.Int
	)

	x.SetBytes(pubk[:BigNubLength])
	y.SetBytes(pubk[BigNubLength:])
	r.SetBytes(sig[:BigNubLength])
	s.SetBytes(sig[BigNubLength:])
	pubkey.Curve = elliptic.P256()
	pubkey.X = &x
	pubkey.Y = &y
	return ecdsa.Verify(&pubkey, hash, &r, &s)
}
