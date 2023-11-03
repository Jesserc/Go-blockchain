package signature

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// jessercID is an arbitrary number for signing messages. This will make it
// clear that the signature comes from the Jesserc blockchain.
// Ethereum and Bitcoin do this as well, but they use the value of 27.
const jessercID = 29

// =============================================================================

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
	// rs gets the recovery id, Jesserc id
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(publicKeyBytes, data, rs) {
		return nil, nil, nil, errors.New("invalid signature produced")
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = toSignatureValues(sig)

	return v, r, s, nil
}

// VerifySignature verifies the signature conforms to our standards.
func VerifySignature(v, r, s *big.Int) error {

	uintV := v.Uint64() - jessercID
	if uintV != 0 && uintV != 1 {
		return errors.New("invalid signature recovery id")
	}

	if !crypto.ValidateSignatureValues(byte(uintV), r, s, false) {
		return errors.New("invalid signature values")
	}

	return nil
}

// FromAddress extracts the address for the account that signed the data.
func FromAddress(value any, v, r, s *big.Int) (string, error) {
	// Prepare the data for public key extraction.
	data, err := stamp(value)
	if err != nil {
		return "", err
	}

	// Convert the [R|S|V] format into the original 65 bytes.
	sig := ToSignatureBytes(v, r, s)

	// Get the public key associated with the signature
	publicKey, err := crypto.SigToPub(data, sig)
	if err != nil {
		return "", err
	}

	address := crypto.PubkeyToAddress(*publicKey).String()
	return address, nil
}

// ToSignatureBytes converts the r, s, v values into a slice of bytes
// with the removal of the jessercID.
func ToSignatureBytes(v, r, s *big.Int) []byte {
	sig := make([]byte, crypto.SignatureLength)

	rBytes := make([]byte, 32) // r and v are 32 bytes each in the signature
	r.FillBytes(rBytes)
	copy(sig, rBytes)

	sBytes := make([]byte, 32) // r and v are 32 bytes each in the signature
	s.FillBytes(sBytes)
	copy(sig[32:], sBytes)

	sig[64] = byte(v.Uint64() - jessercID) // remove our custom id to get original 1 byte v value

	return sig
}

// =============================================================================

// SignatureString returns the signature as a string.
func SignatureString(v, r, s *big.Int) string {
	return hexutil.Encode(ToSignatureBytesWithJessercID(v, r, s))
}

// ToSignatureBytesWithArdanID converts the r, s, v values into a slice of bytes
// keeping the Jesserc id.
func ToSignatureBytesWithJessercID(v, r, s *big.Int) []byte {
	sig := ToSignatureBytes(v, r, s)
	// we set the last value of the sig bytes to the original V value, which is the Jesserc id
	// The reason for this is because the ToSignatureBytes function removes the Jesserc id.
	// This function is meant to have the same logic with the ToSignatureBytes function, except that it preserves the Jesserc id.
	sig[64] = byte(v.Uint64())
	return sig
}

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
