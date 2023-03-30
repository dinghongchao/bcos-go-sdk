package sdk

import (
	"fmt"
	"github.com/dinghongchao/bcos-go-sdk/internal/tx"
	"github.com/dinghongchao/bcos-go-sdk/tars-protocol/bcostars"
)

func CreateUnsignedDeploymentTransaction(groupId string, chainId string, dataHex string, abiJson string, blockLimit int64) (txHash string, txDataHex string, err error) {
	txData, err := tx.CreateTransactionData(groupId, chainId, "", dataHex, abiJson, blockLimit)
	if err != nil {
		return "", "", err
	}
	fmt.Println("txData", txData)

	return createUnsignedTransaction(txData)
}
func CreateUnsignedTransaction(groupId string, chainId string, to string, dataHex string, blockLimit int64) (txHash string, txDataHex string, err error) {
	txData, err := tx.CreateTransactionData(groupId, chainId, to, dataHex, "", blockLimit)
	if err != nil {
		return "", "", err
	}
	fmt.Println("txData", txData)

	return createUnsignedTransaction(txData)
}
func createUnsignedTransaction(txData *bcostars.TransactionData) (txHash string, txDataHex string, err error) {
	txHash, err = tx.CalculateTransactionDataHash(txData)
	if err != nil {
		return "", "", err
	}
	fmt.Println("txHash", txHash)

	txDataHex, err = tx.EncodeTransactionDataToHex(txData)
	if err != nil {
		return "", "", err
	}

	return txHash, txDataHex, nil
}

func SignTransaction(privateKey string, txHash string, txDataHex string, attribute int32) (signedTxDataHex string, err error) {
	txData, err := tx.DecodeTransactionDataFromHex(txDataHex)
	fmt.Println("txData", txData)

	signedTxDataHash, err := tx.SignTransactionDataHash(privateKey, txHash)
	if err != nil {
		return "", err
	}
	fmt.Println("signedTxDataHash", signedTxDataHash)

	from, err := tx.PrivateKeyToAddress(privateKey)
	if err != nil {
		return "", err
	}
	_tx, err := tx.CreateTransaction(from, txData, txHash, signedTxDataHash, attribute)
	if err != nil {
		return "", err
	}

	_txHex, err := tx.EncodeTransaction(_tx)
	if err != nil {
		return "", err
	}
	fmt.Println("_txHex", _txHex)

	return _txHex, nil
}

//txHash string, txHex string, err error
func CreateSignedTransaction(privateKey string, groupId string, chainId string, to string, dataHex string, abiJson string, blockLimit int64) (string, string, error) {
	var txHash, txDataHex string
	var err error
	if to == "" {
		txHash, txDataHex, err = CreateUnsignedDeploymentTransaction(groupId, chainId, dataHex, abiJson, blockLimit)
	} else {
		txHash, txDataHex, err = CreateUnsignedTransaction(groupId, chainId, to, dataHex, blockLimit)
	}
	if err != nil {
		return "", "", err
	}
	signedTxDataHex, err := SignTransaction(privateKey, txHash, txDataHex, 0)
	if err != nil {
		return "", "", err
	}
	return txHash, signedTxDataHex, err
	//return tx.CreateSignedTransaction(privateKey, groupId, chainId, to, dataHex, abiJson, blockLimit, 0)
}
