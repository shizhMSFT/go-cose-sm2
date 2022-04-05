package cosesm2

import "github.com/veraison/go-cose"

// Algorithm value for SM2 defined by draft-dang-webauthn-sm2-00.
//
// Reference: https://datatracker.ietf.org/doc/html/draft-dang-webauthn-sm2-00
const AlgorithmSM2 = -48

func init() {
	cose.RegisterAlgorithm(AlgorithmSM2, "SM2", 0, nil)
}
