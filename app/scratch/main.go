package main

import (
	"encoding/json"
	"fmt"
	"log"

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

	tx := Tx{FromId: "0xff", ToId: "0xcc", Value: 250000}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("unable to generate private key: %w", err)
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	v := crypto.Keccak256(data)

	sig, err := crypto.Sign(v, privateKey)
	// fmt.Printf("sig: %v\n", sig)
	if err != nil {
		return fmt.Errorf("unable to sign tx %w", err)
	}

	fmt.Printf("hex sig: %v\n", hexutil.Encode(sig))
	// fmt.Println(string(sig))
	return nil
}
