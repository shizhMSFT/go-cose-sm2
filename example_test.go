package cosesm2_test

import (
	"crypto/rand"
	"fmt"

	"github.com/need-being/gmcrypto/sm2"
	cosesm2 "github.com/shizhMSFT/go-cose-sm2"
	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign1 signatures using
// SM2.
func Example() {
	// create message to be signed
	msgToSign := cose.NewSign1Message()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Headers.Protected.SetAlgorithm(cosesm2.AlgorithmSM2)

	// create a signer
	privateKey, err := sm2.GenerateKey(sm2.Curve(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := cosesm2.NewSigner(privateKey)

	// sign message
	err = msgToSign.Sign(rand.Reader, signer)
	if err != nil {
		panic(err)
	}
	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	fmt.Println("message signed")

	// create a verifier from a trusted public key
	publicKey := &privateKey.PublicKey
	verifier := cosesm2.NewVerifier(publicKey)

	// verify message
	var msgToVerify cose.Sign1Message
	err = msgToVerify.UnmarshalCBOR(sig)
	if err != nil {
		panic(err)
	}
	err = msgToVerify.Verify(verifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("message verified")

	// tamper the message and verification should fail
	msgToVerify.Payload = []byte("foobar")
	err = msgToVerify.Verify(verifier)
	if err != cose.ErrVerification {
		panic(err)
	}
	fmt.Println("verification error as expected")
	// Output:
	// message signed
	// message verified
	// verification error as expected
}
