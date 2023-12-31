package database

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ardanlabs/blockchain/foundation/blockchain/signature"
)

// Tx is the transactional information between two parties.
type Tx struct {
	ChainID uint16    `json:"chain_id"` // Ethereum: The chain id that is listed in the genesis file.
	Nonce   uint64    `json:"nonce"`    // Ethereum: Unique id for the transaction supplied by the user.
	FromID  AccountID `json:"from"`     // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID    AccountID `json:"to"`       // Ethereum: Account receiving the benefit of the transaction.
	Value   uint64    `json:"value"`    // Ethereum: Monetary value received from this transaction.
	Tip     uint64    `json:"tip"`      // Ethereum: Tip offered by the sender as an incentive to mine this transaction.
	Data    []byte    `json:"data"`     // Ethereum: Extra data related to the transaction.
}

// NewTX constructs a new transaction

func NewTx(chainID uint16, nonce uint64, fromID AccountID, toID AccountID, value uint64, tip uint64, data []byte) (Tx, error) {

	if !fromID.isAccountID() {
		return Tx{}, errors.New("invalid from account, check formatting")
	}

	if !toID.isAccountID() {
		return Tx{}, errors.New("invalid to account, check formatting")
	}

	tx := Tx{
		ChainID: chainID,
		Nonce:   nonce,
		FromID:  fromID,
		ToID:    toID,
		Value:   value,
		Tip:     tip,
		Data:    data,
	}

	return tx, nil
}

func (tx Tx) Sign(privateKey *ecdsa.PrivateKey) (SignedTx, error) {

	v, r, s, err := signature.Sign(tx, privateKey)
	if err != nil {
		return SignedTx{}, err
	}

	signedTx := SignedTx{
		Tx: tx,
		V:  v,
		R:  r,
		S:  s,
	}
	return signedTx, nil
}

// =============================================================================

// SignedTx is a signed version of the transaction. This is how clients like
// a wallet provide transactions for inclusion into the blockchain.
type SignedTx struct {
	Tx
	V *big.Int `json:"v"` // Ethereum: Recovery identifier (1c or 1d for Ethereum), either 29 or 30 with jessercID.
	R *big.Int `json:"r"` // Ethereum: First coordinate of the ECDSA signature.
	S *big.Int `json:"s"` // Ethereum: Second coordinate of the ECDSA signature.
}

// Validate verifies the transaction has a proper signature that conforms to our
// standards. It also checks the from field matches the account that signed the
// transaction. Last it checks the format of the from and to fields.
func (tx SignedTx) Validate(chainID uint16) error {
	if tx.ChainID != chainID {
		return fmt.Errorf("invalid chain id, got[%d], but expected[%d]", chainID, tx.ChainID)
	}

	if !tx.FromID.isAccountID() {
		return errors.New("from account is not properly formatted")
	}
	if !tx.ToID.isAccountID() {
		return fmt.Errorf("to account is not properly formatted")
	}

	// prevent users from sending value to themselves to avoid wasting gas
	if tx.FromID == tx.ToID {
		return fmt.Errorf("transaction invalid, sending money to yourself, from %s, to %s", tx.FromID, tx.ToID)
	}
	if err := signature.VerifySignature(tx.V, tx.R, tx.S); err != nil {
		return err
	}

	address, err := signature.FromAddress(tx.Tx, tx.V, tx.R, tx.S)
	if err != nil {
		return err
	}

	if address != string(tx.Tx.FromID) {
		return errors.New("signature address doesn't match from address")
	}

	return nil
}

func (tx SignedTx) SignatureString() string {
	return signature.SignatureString(tx.V, tx.R, tx.S)
}
