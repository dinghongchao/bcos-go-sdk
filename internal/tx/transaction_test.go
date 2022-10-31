package tx

import (
	"fmt"
	"testing"
)

// 错误编码
// https://github.com/FISCO-BCOS/FISCO-BCOS/blob/be01b860cc5ef57244ddbd6511e20174f5cc4ef5/bcos-protocol/bcos-protocol/TransactionStatus.h
func TestCreateSignedTransaction(t *testing.T) {
	type args struct {
		privateKey string
		groupId    string
		chainId    string
		to         string
		dataHex    string
		abiJson    string
		blockLimit int64
		attribute  int32
	}
	tests := []struct {
		name       string
		args       args
		wantTxHash string
		wantTxHex  string
		wantErr    bool
	}{
		{
			"default",
			args{
				privateKey: "ca5fee2b6c430b26cd13da546ec49cc6a3ce8e5edc5fb0c05cbda11926f255ae",
				groupId:    "group0",
				chainId:    "chain0",
				to:         "0x9af1a9f7cdf77390fb3faa5a60c1b3da8b9a0c35", // 只能给合约发起请求
				dataHex:    "000000",
				abiJson:    "",
				blockLimit: 0,
				attribute:  0,
			},
			"",
			"",
			false,
		},
		{
			"deploy",
			args{
				privateKey: "ca5fee2b6c430b26cd13da546ec49cc6a3ce8e5edc5fb0c05cbda11926f255ae",
				groupId:    "group0",
				chainId:    "chain0",
				dataHex:    "608060405234801561001057600080fd5b506040518060400160405280600d81526020017f48656c6c6f2c20576f72"+
				"6c6421000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50"+
				"610107565b828054600181600116156101000203166002900490600052602060002090601f01602090048101928260"+
				"1f106100a357805160ff19168380011785556100d1565b828001600101855582156100d1579182015b828111156100"+
				"d05782518255916020019190600101906100b5565b5b5090506100de91906100e2565b5090565b61010491905b8082"+
				"11156101005760008160009055506001016100e8565b5090565b90565b610310806101166000396000f3fe60806040"+
				"5234801561001057600080fd5b50600436106100365760003560e01c80634ed3885e1461003b5780636d4ce63c1461"+
				"00f6575b600080fd5b6100f46004803603602081101561005157600080fd5b81019080803590602001906401000000"+
				"0081111561006e57600080fd5b82018360208201111561008057600080fd5b80359060200191846001830284011164"+
				"0100000000831117156100a257600080fd5b91908080601f0160208091040260200160405190810160405280939291"+
				"90818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050"+
				"50610179565b005b6100fe610193565b60405180806020018281038252838181518152602001915080519060200190"+
				"80838360005b8381101561013e578082015181840152602081019050610123565b50505050905090810190601f1680"+
				"1561016b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b8060"+
				"00908051906020019061018f929190610235565b5050565b6060600080546001816001161561010002031660029004"+
				"80601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203"+
				"1660029004801561022b5780601f106102005761010080835404028352916020019161022b565b8201919060005260"+
				"20600020905b81548152906001019060200180831161020e57829003601f168201915b5050505050905090565b8280"+
				"54600181600116156101000203166002900490600052602060002090601f016020900481019282601f106102765780"+
				"5160ff19168380011785556102a4565b828001600101855582156102a4579182015b828111156102a3578251825591"+
				"602001919060010190610288565b5b5090506102b191906102b5565b5090565b6102d791905b808211156102d35760"+
				"008160009055506001016102bb565b5090565b9056fea2646970667358221220b5943f43c48cc93c6d71cdcf27aee5"+
				"072566c88755ce9186e32ce83b24e8dc6c64736f6c634300060a0033",
				abiJson:    "{}",
				blockLimit: 0,
				attribute:  0,
			},
			"",
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTxHash, gotTxHex, err := CreateSignedTransaction(tt.args.privateKey, tt.args.groupId, tt.args.chainId, tt.args.to, tt.args.dataHex, tt.args.abiJson, tt.args.blockLimit, tt.args.attribute)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSignedTransaction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("txHash: %v", gotTxHash)
			t.Logf("txHex: %v", gotTxHex)
			//if gotTxHash != tt.wantTxHash {
			//	t.Errorf("CreateSignedTransaction() gotTxHash = %v, want %v", gotTxHash, tt.wantTxHash)
			//}
			//if gotTxHex != tt.wantTxHex {
			//	t.Errorf("CreateSignedTransaction() gotTxHex = %v, want %v", gotTxHex, tt.wantTxHex)
			//}
		})
	}
}



func TestNonce(t *testing.T) {
	tests := []struct {
		name string
		dontWant string
	}{
		{
			"default",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Nonce()
			fmt.Println(got)
			if got == tt.dontWant {
				t.Errorf("Nonce() = %v, dont't want %v", got, tt.dontWant)
			}
		})
	}
}

func TestPrivateKeyToAddress(t *testing.T) {
	type args struct {
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"default",
			args{privateKey: "ca5fee2b6c430b26cd13da546ec49cc6a3ce8e5edc5fb0c05cbda11926f255ae"},
			"0x743dE6185FA5dEF2794838F67ea050353Ba186B7",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivateKeyToAddress(tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKeyToAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PrivateKeyToAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}