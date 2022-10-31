package crypto

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	common "github.com/dinghongchao/bcos-go-sdk/internal/common"
)

func PubkeyToAddress(p secp256k1.PublicKey) common.Address {
	pubBytes := p.SerializeUncompressed()
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}
