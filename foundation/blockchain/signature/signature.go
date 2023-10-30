package signature

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// jessercID is an arbitrary number for signing messages. This will make it
// clear that the signature comes from the Jesserc blockchain.
// Ethereum and Bitcoin do this as well, but they use the value of 27.
const jessercID = 29

// Sign uses the specified private key to sign the data.
func Sign(value any, privateKey *ecdsa.PrivateKey) (v, r, s *big.Int, err error) {

	// Prepare the data for signing.
	data, err := stamp(value)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sign the hash with the private key to produce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract the bytes for the original public key.
	publicKeyOrg := privateKey.Public()

	// Type assertion (assert and cast the pubkey to type ecdsa.PublicKey, ok will be false if this fails)
	publicKeyECDSA, ok := publicKeyOrg.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// Check the public key validates the data and signature.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(publicKeyBytes, data, rs) {
		return nil, nil, nil, errors.New("invalid signature produced")
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = toSignatureValues(sig)

	return v, r, s, nil
}

// =============================================================================

// stamp returns a hash of 32 bytes that represents this data with
// the Jesserc stamp embedded into the final hash.
func stamp(value any) ([]byte, error) {

	// Marshal the data.
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// This stamp is used so signatures we produce when signing data
	// are always unique to the Jesserc blockchain.
	stamp := []byte(fmt.Sprintf("\x19Jesserc Signed Message:\n%d", len(data)))

	// Hash the stamp and txHash together in a final 32 byte array
	// that represents the data.
	hash := crypto.Keccak256(stamp, data)

	return hash, nil
}

// toSignatureValues converts the signature into the r, s, v values.
func toSignatureValues(sig []byte) (v, r, s *big.Int) {
	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64] + jessercID})

	return v, r, s
}
