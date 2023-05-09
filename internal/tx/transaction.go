package tx

import (
	"encoding/binary"
	"math/big"

	"crypto/rand"
	//ecdsa2 "crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	//"github.com/ethereum/go-ethereum/crypto"
	"github.com/dinghongchao/bcos-go-sdk/internal/crypto"
	//"math/rand"
	//"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/dinghongchao/bcos-go-sdk/internal/common"
	"github.com/dinghongchao/bcos-go-sdk/internal/common/hexutil"
	"github.com/dinghongchao/bcos-go-sdk/tars-protocol/bcostars"
	"strings"
)

//func PackDataHexFromAbiJson(abiJson string, name string, args ...interface{}) ([]byte, error) {
//	parsed, err := abi.JSON(strings.NewReader(abiJson))
//	if err != nil {
//		return nil, err
//	}
//
//	return parsed.Pack(name, args...)
//}

// @todo
func GetBlockLimit(groupId string) (int64, error) {
	return 3333, nil
}

/*
1
*/
func CreateTransactionData(groupId string, chainId string, to string, dataHex string, abiJson string, blockLimit int64) (*bcostars.TransactionData, error) {
	if blockLimit == 0 {
		var err error
		blockLimit, err = GetBlockLimit(groupId)
		if err != nil {
			return nil, err
		}
	}
	nonce, err := Nonce()
	if err != nil {
		return nil, err
	}
	if len(abiJson) > 0 {
		// 合约部署
		return &bcostars.TransactionData{
			Version:    0,
			ChainID:    chainId,
			GroupID:    groupId,
			BlockLimit: blockLimit,
			Nonce:      nonce,
			//To:    "0x0000000000000000000000000000000000000000",
			Input: HexByte2Int8(common.FromHex(dataHex)),
			Abi:   abiJson,
		}, nil
	}

	// 方法调用
	return &bcostars.TransactionData{
		Version:    0,
		ChainID:    chainId,
		GroupID:    groupId,
		BlockLimit: blockLimit,
		Nonce:      nonce,
		To:         strings.ToLower(to),
		//Input:      HexByte2Int8(dataHex),
		Input: HexByte2Int8(common.FromHex(dataHex)),
		Abi:   "",
	}, nil
}
func hash(buf []byte) string {
	// https://github.com/FISCO-BCOS/bcos-crypto/blob/main/bcos-crypto/hash/Keccak256.cpp
	return crypto.Keccak256Hash(buf).Hex()
}
func CalculateTransactionDataHash(txData *bcostars.TransactionData) (string, error) {
	// Keccak256 hash
	buf := codec.NewBuffer()
	//if err := txData.WriteTo(buf); err != nil {
	//	return "", err
	//}
	versionBigEndian := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBigEndian, uint32(txData.Version))
	buf.WriteBytes(versionBigEndian)
	buf.WriteBytes([]byte(txData.ChainID))
	buf.WriteBytes([]byte(txData.GroupID))
	blockLimitBigEndian := make([]byte, 8)
	binary.BigEndian.PutUint64(blockLimitBigEndian, uint64(txData.BlockLimit))
	buf.WriteBytes(blockLimitBigEndian)
	buf.WriteBytes([]byte(txData.Nonce))
	buf.WriteBytes([]byte(txData.To))
	buf.WriteSliceInt8(txData.Input)
	buf.WriteBytes([]byte(txData.Abi))
	//return HexStringWithPrefix(hash(buf.ToBytes())), nil
	//fmt.Println(buf.ToBytes())
	return hash(buf.ToBytes()), nil
}

func Nonce() (string, error) {
	// generate random Nonce between 0 - 2^250 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(250), nil).Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	nonce, err := rand.Int(rand.Reader, max)
	if err != nil {
		//error handling
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	return nonce.String(), nil
}

func PrivateKeyToAddress(privateKey string) (string, error) {
	privKey, err := ParseKeyPairFromPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	//// 获取公钥并去除头部0x04
	//compressed := privKey.PubKey().SerializeUncompressed()[1:]
	//fmt.Printf("公钥为x: %s\n", hex.EncodeToString(compressed))

	//// 获取地址
	addr := crypto.PubkeyToAddress(*privKey.PubKey())
	//fmt.Printf("地址为: %s\n", addr.Hex())

	return addr.Hex(), nil
}

func ParseKeyPairFromPrivateKey(privateKey string) (*secp256k1.PrivateKey, error) {
	// Decode a hex-encoded private key.
	pkBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	privKey := secp256k1.PrivKeyFromBytes(pkBytes)

	return privKey, nil
}

func SignTransactionDataHash(privateKey string, txDataHash string) (string, error) {
	privKey, err := ParseKeyPairFromPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	//Sign a message using the private key.
	messageHash := txDataHash
	signature := ecdsa.Sign(privKey, []byte(messageHash))

	// Serialize and display the signature.
	//fmt.Printf("Serialized Signature: %x\n", signature.Serialize())

	// Verify the signature for the message using the public key.
	//pubKey := privKey.PubKey()
	//verified := signature.Verify([]byte(messageHash), pubKey)
	//fmt.Printf("Signature Verified? %v\n", verified)

	return hexutil.Encode(signature.Serialize()), nil

	// 原本的ecdsa签名
	//priKey, err := crypto.HexToECDSA(privateKey)
	//if err != nil {
	//	panic(err)
	//}
	//priKeyBytes := crypto.FromECDSA(priKey)
	//fmt.Printf("私钥为: %s\n", hex.EncodeToString(priKeyBytes))
	//pubKey := priKey.Public().(*ecdsa2.PublicKey)
	//// 获取公钥并去除头部0x04
	//pubKeyBytes := crypto.FromECDSAPub(pubKey)[1:]
	//fmt.Printf("公钥为: %s\n", hex.EncodeToString(pubKeyBytes))
	//// 获取地址
	//addr := crypto.PubkeyToAddress(*pubKey)
	//fmt.Printf("地址为: %s\n", addr.Hex())
	//
	//messageHash := common.HexToHash(txDataHash).Bytes()
	//sig, err := crypto.Sign(messageHash[:], priKey)
	//return hexutil.Encode(sig), nil
}

//	func Address(priKey *ecdsa2.PrivateKey) string {
//		//priKeyHash := "796c823671b118258b53ef6056fd1f9fc96d125600f348f75f397b2000267fe8"
//		// 创建私钥对象，上面私钥没有钱哦
//		//priKey, err := crypto.HexToECDSA(priKeyHash)
//		//if err != nil {
//		//	panic(err)
//		//}
//		//priKeyBytes := crypto.FromECDSA(priKey)
//		//fmt.Printf("私钥为: %s\n", hex.EncodeToString(priKeyBytes))
//
//		pubKey := priKey.Public().(*ecdsa2.PublicKey)
//		//// 获取公钥并去除头部0x04
//		pubKeyBytes := crypto.FromECDSAPub(pubKey)[1:]
//		fmt.Printf("公钥为: %s\n", hex.EncodeToString(pubKeyBytes))
//		//
//		//// 获取地址
//		addr := crypto.PubkeyToAddress(*pubKey)
//		fmt.Printf("地址为: %s\n", addr.Hex())
//
//		return addr.Hex()
//	}
func CreateTransaction(from string, txData *bcostars.TransactionData, txDataHash string, signedTxDataHash string, attribute int32) (*bcostars.Transaction, error) {
	return &bcostars.Transaction{
		Data:       *txData,
		DataHash:   HexByte2Int8(common.FromHex(txDataHash)),
		Signature:  HexByte2Int8(common.FromHex(signedTxDataHash)),
		ImportTime: 0,
		Attribute:  attribute,
		ExtraData:  "",
		Sender:     HexByte2Int8(common.FromHex(strings.ToLower(from))),
	}, nil
}
func EncodeTransaction(tx *bcostars.Transaction) (string, error) {
	buf := codec.NewBuffer()
	if err := tx.WriteTo(buf); err != nil {
		return "", err
	}
	return hexutil.Encode(buf.ToBytes()), nil
}
func CreateSignedTransaction(privateKey string, groupId string, chainId string, to string, dataHex string, abiJson string, blockLimit int64, attribute int32) (txHash string, txHex string, err error) {
	txData, err := CreateTransactionData(groupId, chainId, to, dataHex, abiJson, blockLimit)
	if err != nil {
		return "", "", err
	}
	//fmt.Println("txData", txData)

	txDataHash, err := CalculateTransactionDataHash(txData)
	if err != nil {
		return "", "", err
	}
	//fmt.Println("txDataHash", txDataHash)

	signedTxDataHash, err := SignTransactionDataHash(privateKey, txDataHash)
	if err != nil {
		return "", "", err
	}
	//fmt.Println("signedTxDataHash", signedTxDataHash)

	from, err := PrivateKeyToAddress(privateKey)
	if err != nil {
		return "", "", err
	}
	tx, err := CreateTransaction(from, txData, txDataHash, signedTxDataHash, attribute)
	if err != nil {
		return "", "", err
	}

	_txHex, err := EncodeTransaction(tx)
	if err != nil {
		return "", "", err
	}
	//fmt.Println("_txHex", _txHex)

	return txDataHash, _txHex, nil
}

func CreateSignedTransactionReturnNonce(privateKey string, groupId string, chainId string, to string, dataHex string, abiJson string, blockLimit int64, attribute int32) (txHash string, txHex string, nonce string, err error) {
	txData, err := CreateTransactionData(groupId, chainId, to, dataHex, abiJson, blockLimit)
	if err != nil {
		return "", "", "", err
	}
	nonce = txData.Nonce
	//fmt.Println("txData", txData)

	txDataHash, err := CalculateTransactionDataHash(txData)
	if err != nil {
		return "", "", "", err
	}
	//fmt.Println("txDataHash", txDataHash)

	signedTxDataHash, err := SignTransactionDataHash(privateKey, txDataHash)
	if err != nil {
		return "", "", "", err
	}
	//fmt.Println("signedTxDataHash", signedTxDataHash)

	from, err := PrivateKeyToAddress(privateKey)
	if err != nil {
		return "", "", "", err
	}
	tx, err := CreateTransaction(from, txData, txDataHash, signedTxDataHash, attribute)
	if err != nil {
		return "", "", "", err
	}

	_txHex, err := EncodeTransaction(tx)
	if err != nil {
		return "", "", "", err
	}
	//fmt.Println("_txHex", _txHex)

	return txDataHash, _txHex, nonce, nil
}

func HexByte2Int8(dataHex []byte) []int8 {
	var dataHexInt8 []int8
	for _, d := range dataHex {
		dataHexInt8 = append(dataHexInt8, int8(d))
	}
	return dataHexInt8
}

func EncodeTransactionDataToHex(tx *bcostars.TransactionData) (string, error) {
	buf := codec.NewBuffer()
	if err := tx.WriteTo(buf); err != nil {
		return "", err
	}

	return hexutil.Encode(buf.ToBytes()), nil
}
func DecodeTransactionDataFromHex(txDataHex string) (*bcostars.TransactionData, error) {
	decode, err := hexutil.Decode(txDataHex)
	if err != nil {
		return nil, err
	}
	buf := codec.NewReader(decode)

	txData := &bcostars.TransactionData{}
	if err := txData.ReadFrom(buf); err != nil {
		return nil, err
	}

	return txData, nil
}
