package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Transaction struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp int64                  `json:"timestamp"`
}

type Block struct {
	Index        int           `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	MerkleRoot   string        `json:"merkle_root"`
	PrevHash     string        `json:"prev_hash"`
	Nonce        int           `json:"nonce"`
	Hash         string        `json:"hash"`
}

type BlockchainModule struct {
	chain      []*Block
	pending    []Transaction
	difficulty int
	dataDir    string
}

func NewBlockchainModule(dataDir string, difficulty int) (*BlockchainModule, error) {
	bcDir := filepath.Join(dataDir, "blockchain")
	if err := os.MkdirAll(bcDir, 0700); err != nil {
		return nil, err
	}

	bc := &BlockchainModule{
		chain:      make([]*Block, 0),
		pending:    make([]Transaction, 0),
		difficulty: difficulty,
		dataDir:    dataDir,
	}

	if err := bc.loadChain(); err != nil {
		bc.createGenesisBlock()
	}

	return bc, nil
}

func (bc *BlockchainModule) createGenesisBlock() {
	genesis := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: []Transaction{},
		MerkleRoot:   "0",
		PrevHash:     "0",
		Nonce:        0,
	}
	genesis.Hash = bc.calculateHash(genesis)
	bc.chain = append(bc.chain, genesis)
	bc.saveChain()
}

// AddTransaction adds a transaction to pending pool
func (bc *BlockchainModule) AddTransaction(txType string, data map[string]interface{}) {
	tx := Transaction{
		Type:      txType,
		Data:      data,
		Timestamp: time.Now().Unix(),
	}
	bc.pending = append(bc.pending, tx)

	if len(bc.pending) >= 5 {
		bc.MineBlock()
	}
}

// MineBlock mines a new block with pending transactions
func (bc *BlockchainModule) MineBlock() error {
	if len(bc.pending) == 0 {
		return errors.New("no pending transactions")
	}

	prevBlock := bc.chain[len(bc.chain)-1]

	newBlock := &Block{
		Index:        len(bc.chain),
		Timestamp:    time.Now().Unix(),
		Transactions: bc.pending,
		PrevHash:     prevBlock.Hash,
		Nonce:        0,
	}

	newBlock.MerkleRoot = bc.buildMerkleRoot(bc.pending)

	target := strings.Repeat("0", bc.difficulty)
	for {
		newBlock.Hash = bc.calculateHash(newBlock)
		if strings.HasPrefix(newBlock.Hash, target) {
			break
		}
		newBlock.Nonce++
	}

	bc.chain = append(bc.chain, newBlock)
	bc.pending = []Transaction{}

	bc.saveChain()

	fmt.Printf("✓ Block #%d mined (nonce: %d, hash: %s)\n",
		newBlock.Index, newBlock.Nonce, newBlock.Hash[:16])

	return nil
}

// buildMerkleRoot builds Merkle tree from transactions
func (bc *BlockchainModule) buildMerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return ""
	}

	var hashes []string
	for _, tx := range txs {
		data, _ := json.Marshal(tx)
		hash := sha256.Sum256(data)
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}

	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newLevel []string
		for i := 0; i < len(hashes); i += 2 {
			combined := hashes[i] + hashes[i+1]
			hash := sha256.Sum256([]byte(combined))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		}
		hashes = newLevel
	}

	return hashes[0]
}

// calculateHash calculates block hash
func (bc *BlockchainModule) calculateHash(block *Block) string {
	record := fmt.Sprintf("%d%d%s%s%s%d",
		block.Index,
		block.Timestamp,
		block.MerkleRoot,
		block.PrevHash,
		block.Transactions,
		block.Nonce,
	)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// ValidateChain validates the entire blockchain
func (bc *BlockchainModule) ValidateChain() bool {
	for i := 1; i < len(bc.chain); i++ {
		curr := bc.chain[i]
		prev := bc.chain[i-1]

		if curr.Hash != bc.calculateHash(curr) {
			fmt.Printf("Invalid hash at block %d\n", i)
			return false
		}

		if curr.PrevHash != prev.Hash {
			fmt.Printf("Invalid previous hash at block %d\n", i)
			return false
		}

		target := strings.Repeat("0", bc.difficulty)
		if !strings.HasPrefix(curr.Hash, target) {
			fmt.Printf("Invalid proof of work at block %d\n", i)
			return false
		}
	}
	return true
}

// SearchTransactions finds transactions matching criteria
func (bc *BlockchainModule) SearchTransactions(txType, userHash string) []Transaction {
	var results []Transaction
	for _, block := range bc.chain {
		for _, tx := range block.Transactions {
			if txType != "" && tx.Type != txType {
				continue
			}
			if userHash != "" {
				if uh, ok := tx.Data["user_hash"].(string); !ok || uh != userHash {
					continue
				}
			}
			results = append(results, tx)
		}
	}
	return results
}

// GetChain returns the current blockchain
func (bc *BlockchainModule) GetChain() []*Block {
	return bc.chain
}

// saveChain saves blockchain to disk
func (bc *BlockchainModule) saveChain() error {
	data, err := json.MarshalIndent(bc.chain, "", "  ")
	if err != nil {
		return err
	}

	chainPath := filepath.Join(bc.dataDir, "blockchain", "chain.json")
	return os.WriteFile(chainPath, data, 0600)
}

// loadChain loads blockchain from disk
func (bc *BlockchainModule) loadChain() error {
	chainPath := filepath.Join(bc.dataDir, "blockchain", "chain.json")
	data, err := os.ReadFile(chainPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &bc.chain)
}
