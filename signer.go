package cosesm2

import (
	"io"

	"github.com/need-being/gmcrypto/sm2"
	"github.com/veraison/go-cose"
)

type signer struct {
	key *sm2.PrivateKey
}

// NewSigner returns a signer with a given signing key.
func NewSigner(key *sm2.PrivateKey) cose.Signer {
	return &signer{
		key: key,
	}
}

// Algorithm returns the signing algorithm associated with the private key.
func (s *signer) Algorithm() cose.Algorithm {
	return AlgorithmSM2
}

// Sign signs message with the private key, possibly using entropy from rand.
func (s *signer) Sign(rand io.Reader, message []byte) ([]byte, error) {
	return sm2.Sign(rand, s.key, message)
}
