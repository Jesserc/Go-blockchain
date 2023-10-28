// Package genesis maintains access to the genesis file in "zblock/genesis.json".
package genesis

import (
	"encoding/json"
	"os"
	"time"
)

type Genesis struct {
	Date          time.Time         `json:"date"`
	ChainID       uint16            `json:"chain_id"`        // The chain id represents an unique id for this running instance.
	TransPerBlock uint16            `json:"trans_per_block"` // The maximum number of transactions that can be in a block.
	Difficulty    uint16            `json:"difficulty"`      // How difficult it needs to be to solve the work problem.
	MiningReward  uint16            `json:"mining_reward"`   // Reward for mining a block.
	Gasprice      uint16            `json:"gas_price"`       // Fee paid for each transaction mined into a block.
	Balances      map[string]uint64 `json:"balances"`        // A map of "address" to their balance
}

// =============================================================================

// Load opens and consumes the genesis file.
func Load() (Genesis, error) {
	path := "zblock/genesis.json"
	content, err := os.ReadFile(path)
	if err != nil {
		return Genesis{}, err
	}

	var genesis Genesis
	err = json.Unmarshal(content, &genesis)
	if err != nil {
		return Genesis{}, err
	}

	return genesis, nil
}

/*

save this elsewhere later

// Package genesis maintains access to the genesis file.
package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type Genesis struct {
	Date          time.Time         `json:"date"`
	ChainID       uint16            `json:"chain_id"`        // The chain id represents an unique id for this running instance.
	TransPerBlock uint16            `json:"trans_per_block"` // The maximum number of transactions that can be in a block.
	Difficulty    uint16            `json:"difficulty"`      // How difficult it needs to be to solve the work problem.
	MiningReward  uint16            `json:"mining_reward"`   // Reward for mining a block.
	Gasprice      uint16            `json:"gas_price"`       // Fee paid for each transaction mined into a block.
	Balances      map[string]uint64 `json:"balances"`        // A map of "address" to their balance
}

func main() {
	g := Genesis{Date: time.Now(),...}
	jsonData, _ := json.Marshal(g)
	fmt.Println(string(jsonData)) // Output: {"date":"2023-10-28T14:45:00Z"}
}

*/
