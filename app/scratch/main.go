package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/ardanlabs/blockchain/foundation/blockchain/database"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type Tx struct {
	FromId string `json:"from"`
	ToId   string `json:"To"`
	Value  uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {

	// privateKey, err := crypto.GenerateKey()
	privateKey, err := crypto.LoadECDSA("zblock/accounts/jesserc.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to generate private key: %w", err)
	}

	tx := Tx{
		FromId: "0xa97a146642b60Fbc7E1b096455F6D144b15fd75d",
		ToId:   "0xcc",
		Value:  80000,
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	// salt the encoded tx data just like Ethereum and Bitcoin
	// sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message))) for Ethereum
	// stamp := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n32"))
	stamp := []byte(fmt.Sprintf("\x19Jesserc Signed Message:\n%d", len(data)))
	hashOfData := crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(hashOfData, privateKey)
	// fmt.Printf("sig: %v\n", sig)
	if err != nil {
		return fmt.Errorf("unable to sign tx: %w", err)
	}

	fmt.Printf("SIG: %v\n\n", hexutil.Encode(sig))

	// =============================================================================
	// OVER THE WIRE

	publicKey, err := crypto.SigToPub(hashOfData, sig)
	if err != nil {
		return fmt.Errorf("unable to generate public key: %w", err)
	}

	pk := crypto.PubkeyToAddress(*publicKey).String()

	fmt.Printf("PUBLIC KEY: %v\n\n", pk)

	// =============================================================================
	// Second transaction and signature generation
	// Always ensure that the `hash of sig`,
	// is the correct hash for the `sig` being passed to the `crypto.Sign(hashDigest, sig)` function
	// else a different public key would be generated and it would'nt match that of the `From` field in the transaction

	tx2 := Tx{
		FromId: "0xa97a146642b60Fbc7E1b096455F6D144b15fd75d",
		ToId:   "0xff",
		Value:  90000,
	}

	data2, err := json.Marshal(tx2)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	// salt the encoded tx data just like Ethereum and Bitcoin
	// stamp := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n32"))
	stamp2 := []byte(fmt.Sprintf("\x19Jesserc Signed Message:\n%d", len(data)))
	hashOfData2 := crypto.Keccak256(stamp2, data2)

	sig2, err := crypto.Sign(hashOfData2, privateKey)
	// fmt.Printf("sig: %v\n", sig)
	if err != nil {
		return fmt.Errorf("unable to sign tx: %w", err)
	}

	// signatures are split into 3 components r,s,v (by order)
	// r => first 32 bytes of the signature
	// s => second 32 bytes of the signature
	// v => last one byte of the signature
	// by default, v is either 00 or 01, but Ethereum customized it's signature implementation to end with 1c (for 01) or 1b (for 00)
	// we'll do a similar thing
	fmt.Printf("SIG 2: %v\n\n", hexutil.Encode(sig2))

	publicKey2, err := crypto.SigToPub(hashOfData2, sig2)
	if err != nil {
		return fmt.Errorf("unable to generate public key: %w", err)
	}

	pk2 := crypto.PubkeyToAddress(*publicKey2).String()
	fmt.Printf("PUBLIC KEY 2: %v\n\n", pk2)

	v, r, s, err := ToVRSFromHexSignature(hexutil.Encode(sig2))
	if err != nil {
		return fmt.Errorf("unable to extract vrs from signature: %w", err)
	}

	fmt.Printf("vrs of signature two:\nv: %d, r: %d, s: %d\n\n", v, r, s)

	// =============================================================================
	fmt.Println("====================================== New Tx ======================================")

	newTx, err := database.NewTx(
		1,
		0,
		"0xa97a146642b60Fbc7E1b096455F6D144b15fd75d",
		"0xffac146642b60Fbc7E1b096455F6D144b15fdfff",
		100000,
		0,
		[]byte("Sent by Jesserc"),
	)

	if err != nil {
		return fmt.Errorf("unable to create tx: %w", err)
	}

	var signedTx database.SignedTx

	signedTx, err = newTx.Sign(privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign new tx: %w", err)
	}
	fmt.Printf("Signed Transaction:\n %v\n", signedTx)

	return nil
}

func ToVRSFromHexSignature(sigStr string) (v, r, s *big.Int, err error) {
	sig, err := hex.DecodeString(sigStr[2:])
	if err != nil {
		return nil, nil, nil, err
	}

	// extract v,r,s
	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64]})

	return v, r, s, nil
}
