package database

import (
	"errors"
)

// AccountID represents an account id that is used to sign transactions and is
// associated with transactions on the blockchain. This will be the last 20
// bytes of the public key.
type AccountID string

func ToAccountID(hex string) (AccountID, error) {

	a := AccountID(hex)

	if !a.isAccountID() {
		return "", errors.New("invalid account format")
	}

	return a, nil
}

// IsAccountID verifies whether the underlying data represents a valid
// hex-encoded account.
func (a AccountID) isAccountID() bool {
	const addressLength = 20

	if has0xPrefix(a) {
		a = a[2:]
	}

	// return `true`, if `a` is 20 bytes long (40 hex characters) and is also hex
	return len(a) == 2*addressLength && isHex(a)
}

// =============================================================================

// has0xPrefix validates the account starts with a 0x.
func has0xPrefix(a AccountID) bool {
	return len(a) >= 2 && a[0] == '0' && (a[1] == 'x' || a[1] == 'X')
}

// isHex validates whether each byte is valid hexadecimal string.
func isHex(a AccountID) bool {
	if len(a)%2 != 0 {
		return false
	}

	for _, c := range []byte(a) {
		if !isHexCharacter(c) {
			return false
		}
	}

	return true
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}
