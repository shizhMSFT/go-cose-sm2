package cosesm2

import (
	"github.com/need-being/gmcrypto/sm2"
	"github.com/veraison/go-cose"
)

type verifier struct {
	key *sm2.PublicKey
}

// NewVerifier returns a verifier with a given public key.
func NewVerifier(key *sm2.PublicKey) cose.Verifier {
	return &verifier{
		key: key,
	}
}

// Algorithm returns the signing algorithm associated with the public key.
func (v *verifier) Algorithm() cose.Algorithm {
	return AlgorithmSM2
}

// Verify verifies message with the public key, returning nil for success.
// Otherwise, it returns an error.
func (v *verifier) Verify(message []byte, signature []byte) error {
	if sm2.Verify(v.key, message, signature) {
		return nil
	}
	return cose.ErrVerification
}
