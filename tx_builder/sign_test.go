package tx_builder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Xrpinals-Protocol/XrpinalsMintTool/utils"
	"strconv"
	"strings"
	"testing"
)

// transfer base asset to normal account
func TestSignTx1(t *testing.T) {
	refBlockNum, refBlockPrefix, err := utils.GetRefBlockInfo(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(refBlockNum)
	fmt.Println(refBlockPrefix)

	chainId, err := utils.GetChainId(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}

	fromAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	toAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	amount := uint64(100000)
	fee := uint64(100000)

	_, _, tx, err := BuildTxTransfer(refBlockNum, refBlockPrefix, fromAddr, toAddr, amount, fee)
	if err != nil {
		t.Fatal(err.Error())
	}

	keyWif := "5JF7asAXBFzGbnLDdLyKqrkRGGKcSJByU22fvzejdU6TdLGimdf"
	txSig, txSigned, err := SignTx(chainId, tx, keyWif)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx1 Sig:", hex.EncodeToString(txSig))
	txJson, err := json.Marshal(*txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx1 Tx:", string(txJson))
}

// mint asset
func TestSignTx2(t *testing.T) {
	refBlockNum, refBlockPrefix, err := utils.GetRefBlockInfo(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(refBlockNum)
	fmt.Println(refBlockPrefix)

	chainId, err := utils.GetChainId(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}

	resp, err := utils.GetAssetInfo(walletUrl, "BTC")
	if err != nil {
		t.Fatal(err.Error())
	}

	issueAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	issueAssetId := resp.Result.Id
	l := strings.Split(resp.Result.Id, ".")
	issueAssetIdNum, err := strconv.Atoi(l[len(l)-2])
	if err != nil {
		t.Fatal(err.Error())
	}
	issueAmount := resp.Result.Options.MaxPerMint
	fee := uint64(100000)

	_, _, tx, err := BuildTxMint(refBlockNum, refBlockPrefix, issueAddr, issueAssetId, int64(issueAssetIdNum), int64(issueAmount), fee)
	if err != nil {
		t.Fatal(err.Error())
	}

	keyWif := "5JF7asAXBFzGbnLDdLyKqrkRGGKcSJByU22fvzejdU6TdLGimdf"
	txSig, txSigned, err := SignTx(chainId, tx, keyWif)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx2 Sig:", hex.EncodeToString(txSig))
	txJson, err := json.Marshal(*txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx2 Tx:", string(txJson))
}

func TestBroadcastTx1(t *testing.T) {
	refBlockNum, refBlockPrefix, err := utils.GetRefBlockInfo(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(refBlockNum)
	fmt.Println(refBlockPrefix)

	chainId, err := utils.GetChainId(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}

	fromAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	toAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	amount := uint64(100000)
	fee := uint64(100000)

	txHashCalc, _, tx, err := BuildTxTransfer(refBlockNum, refBlockPrefix, fromAddr, toAddr, amount, fee)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("BuildTxTransfer txHash:", txHashCalc)

	keyWif := "5JF7asAXBFzGbnLDdLyKqrkRGGKcSJByU22fvzejdU6TdLGimdf"
	txSig, txSigned, err := SignTx(chainId, tx, keyWif)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx1 Sig:", hex.EncodeToString(txSig))

	txJson, err := json.Marshal(*txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx1 Tx:", string(txJson))

	txHash, err := utils.BroadcastTx(walletUrl, txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("BroadcastTx1 txHash:", txHash)
}

func TestBroadcastTx2(t *testing.T) {
	refBlockNum, refBlockPrefix, err := utils.GetRefBlockInfo(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println(refBlockNum)
	fmt.Println(refBlockPrefix)

	chainId, err := utils.GetChainId(walletUrl)
	if err != nil {
		t.Fatal(err.Error())
	}

	resp, err := utils.GetAssetInfo(walletUrl, "FF")
	if err != nil {
		t.Fatal(err.Error())
	}

	issueAddr := "mfhGJnP5T7A5kYDJNxnHozxrVzC7WKHzKs"
	issueAssetId := resp.Result.Id
	l := strings.Split(resp.Result.Id, ".")
	issueAssetIdNum, err := strconv.Atoi(l[len(l)-2])
	if err != nil {
		t.Fatal(err.Error())
	}
	issueAmount := resp.Result.Options.MaxPerMint
	fee := uint64(100000)

	txHashCalc, _, tx, err := BuildTxMint(refBlockNum, refBlockPrefix, issueAddr, issueAssetId, int64(issueAssetIdNum), int64(issueAmount), fee)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("BuildTxMint txHash:", txHashCalc)

	keyWif := "5JF7asAXBFzGbnLDdLyKqrkRGGKcSJByU22fvzejdU6TdLGimdf"
	txSig, txSigned, err := SignTx(chainId, tx, keyWif)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx2 Sig:", hex.EncodeToString(txSig))

	txJson, err := json.Marshal(*txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("SignTx2 Tx:", string(txJson))

	txHash, err := utils.BroadcastTx(walletUrl, txSigned)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("BroadcastTx2 txHash:", txHash)
}