package mining

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xrpinals/XrpinalsMintTool/bitcoin"
	"github.com/xrpinals/XrpinalsMintTool/conf"
	. "github.com/xrpinals/XrpinalsMintTool/logger"
	"github.com/xrpinals/XrpinalsMintTool/tx_builder"
	"github.com/xrpinals/XrpinalsMintTool/utils"
)

var (
	MinerNum  = 1
	Difficult uint32
)

var (
	PrivateKey    = ""
	MintAssetName = ""
)

type Miner struct{}

func init() {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	if numCPU > 1 {
		MinerNum = numCPU - 1
	}
}

func preCheck(assetInfo *utils.AssetInfoRsp) error {
	addr, err := tx_builder.WifKeyToAddr(PrivateKey)
	if err != nil {
		return err
	}

	maxMintCountLimit, err := utils.Uint64Supply(assetInfo.Result.Options.MaxMintCountLimit)
	if err != nil {
		return err
	}

	maxSupply, err := utils.Uint64Supply(assetInfo.Result.Options.MaxSupply)
	if err != nil {
		return err
	}

	currentSupply, err := utils.Uint64Supply(assetInfo.Result.DynamicData.CurrentSupply)
	if err != nil {
		return err
	}

	mintInfo, err := utils.GetAddressMintInfo(conf.GetConfig().WalletRpcUrl, addr, MintAssetName)
	if err != nil {
		return err
	}

	lastMintTime, err := utils.DataTimeToTimestamp(mintInfo.Result.Time)
	if err != nil {
		return err
	}

	if time.Now().Unix()-lastMintTime < assetInfo.Result.Options.MintInterval {
		return errors.New("less than the mint interval")
	}

	if mintInfo.Result.MintCount >= maxMintCountLimit {
		return errors.New("address had mint max count")
	}

	if mintInfo.Result.Amount+currentSupply > maxSupply {
		return errors.New("beyond max mint amount")
	}

	return nil
}

func StartMining() {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := utils.GetAssetInfo(conf.GetConfig().WalletRpcUrl, MintAssetName)
	if err != nil {
		fmt.Println(utils.BoldRed("[Error]: "), utils.FgWhiteBgRed(err.Error()))
		return
	}
	if !resp.Result.Options.Brc20Token {
		fmt.Println(utils.FgWhiteBgRed("not brc20 token, can not mint"))
		return
	}

	err = preCheck(resp)
	if err != nil {
		fmt.Println(utils.BoldRed("[Error]: "), utils.FgWhiteBgRed(err.Error()))
		return
	}

	Difficult = resp.Result.DynamicData.CurrentNBits
	fmt.Printf("Difficult: %v\n", Difficult)

	var wg sync.WaitGroup
	hashCountChan := make(chan int32, 20000000)
	resultChan := make(chan uint64)

	var totalHashCount int32 = 0

	ticker := time.NewTicker(1 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				hashesPerSecond := float64(totalHashCount) / 1000000

				fmt.Printf("[%s] Total hashes per second: %8.2f M/s\n", timestamp, hashesPerSecond)
				// Logger.Infof("[%s] Total hashes per second: %8.2f M/s", timestamp, hashesPerSecond)
				totalHashCount = 0
			case count := <-hashCountChan:
				totalHashCount += count
			}
		}
	}()

	for i := 0; i < MinerNum; i++ {
		wg.Add(1)
		miner := Miner{}
		go miner.mining(&wg, ctx, hashCountChan, resultChan, i == 0)
	}

	nonce := <-resultChan
	fmt.Printf("nonce: %v\n", nonce)
	ticker.Stop()
	cancel()
	wg.Wait()

}

func (m *Miner) buildMintTx() (string, *tx_builder.Transaction, error) {
	// build mint tx
	txHash, tx, err := m.getMintTx()
	if err != nil {
		Logger.Errorf("buildMintTx: getMintTx err: %v", err)
		return "", nil, err
	}
	return txHash, tx, nil
}

func (m *Miner) signMintTx(tx *tx_builder.Transaction) (*tx_builder.Transaction, error) {
	chainId, err := utils.GetChainId(conf.GetConfig().WalletRpcUrl)
	if err != nil {
		Logger.Errorf("signMintTx: GetChainId err: %v", err)
		return nil, err
	}

	_, txSigned, err := tx_builder.SignTx(chainId, tx, PrivateKey)
	if err != nil {
		Logger.Errorf("signMintTx: SignTx err: %v", err)
		return nil, err
	}

	return txSigned, nil
}

func (m *Miner) mining(wg *sync.WaitGroup, ctx context.Context, hashCountChan chan<- int32, resultChan chan<- uint64, statHash bool) {
	defer wg.Done()

	var cycle_times int64 = 10000
	var randomNonce *big.Int
	var nonce uint64
	var err error

	if err != nil {
		Logger.Errorf("mining: rand.Int err: %v", err)
		return
	}

	txHash, unSignedTx, err := m.buildMintTx()
	if err != nil {
		Logger.Errorf("mining: buildMintTx err: %v", err)
		return
	}
	target := bitcoin.NBits2Target(10)
	Logger.Printf("mining: target: %v", target)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			max_number := new(big.Int).Lsh(big.NewInt(1), 256)
			max_number = max_number.Sub(max_number, big.NewInt(cycle_times))
			randomNonce, err = rand.Int(rand.Reader, max_number)

			if err != nil {
				Logger.Errorf("mining: rand.Int err: %v", err)
			}

			nonce = randomNonce.Uint64()
			for i := 0; i < int(cycle_times); i++ {
				payload := PowPayload{
					Version:  1,
					TxHash:   txHash,
					Reserved: [44]byte{},
					NBits:    Difficult,
					Nonce:    nonce,
				}

				payloadBytes, err := payload.pack()
				if err != nil {
					Logger.Errorf("mining: payload.pack err: %v", err)
					return
				}

				s256 := sha256.New()
				_, err = s256.Write(payloadBytes)
				if err != nil {
					Logger.Errorf("mining: s256.Write err: %v", err)
					return
				}
				hashBytes := s256.Sum(nil)
				result := new(big.Int).SetBytes(hashBytes)

				if result.Cmp(target) < 0 {
					resultChan <- nonce
					// broadcast tx
					unSignedTx.NoncePow = nonce
					signedTx, err := m.signMintTx(unSignedTx)
					if err != nil {
						Logger.Errorf("mining: signMintTx err: %v", err)
						return
					}

					_, err = utils.BroadcastTx(conf.GetConfig().WalletRpcUrl, signedTx)
					if err != nil {
						fmt.Printf("mining failed: err: %v\n", err)
						Logger.Errorf("mining: utils.BroadcastTx err: %v", err)
						return
					}

					fmt.Println(utils.BoldYellow("[Info]: "), utils.Bold("mining success, txHash: "), utils.FgWhiteBgBlue(txHash))
					Logger.Infof("mining success, txHash:%v", txHash)
				}
				nonce++
			}

			hashCountChan <- int32(cycle_times)
		}
	}
}

func (m *Miner) getMintTx() (string, *tx_builder.Transaction, error) {
	refBlockNum, refBlockPrefix, err := utils.GetRefBlockInfo(conf.GetConfig().WalletRpcUrl)
	if err != nil {
		return "", nil, err
	}

	resp, err := utils.GetAssetInfo(conf.GetConfig().WalletRpcUrl, MintAssetName)
	if err != nil {
		return "", nil, err
	}

	if !resp.Result.Options.Brc20Token {
		return "", nil, fmt.Errorf("not brc20 token, can not mint")
	}

	issueAddr, err := tx_builder.WifKeyToAddr(PrivateKey)
	if err != nil {
		return "", nil, err
	}

	issueAssetId := resp.Result.Id
	l := strings.Split(resp.Result.Id, ".")
	issueAssetIdNum, err := strconv.Atoi(l[len(l)-1])
	if err != nil {
		return "", nil, err
	}
	issueAmount, err := utils.Uint64Supply(resp.Result.Options.MaxPerMint)
	if err != nil {
		return "", nil, err
	}
	fee := uint64(100)

	txHashCalc, _, tx, err := tx_builder.BuildTxMint(refBlockNum, refBlockPrefix, issueAddr, issueAssetId, int64(issueAssetIdNum), int64(issueAmount), fee)
	if err != nil {
		return "", nil, err
	}

	return txHashCalc, tx, nil
}

type PowPayload struct {
	Version  uint32
	TxHash   string
	Reserved [44]byte
	NBits    uint32
	Nonce    uint64
}

func (p *PowPayload) pack() ([]byte, error) {
	bytesRet := make([]byte, 0)

	bytesRet = append(bytesRet, tx_builder.PackUint32(p.Version)...)

	hashBytes, err := hex.DecodeString(p.TxHash)
	if err != nil {
		return nil, err
	}
	bytesRet = append(bytesRet, hashBytes...)
	bytesRet = append(bytesRet, p.Reserved[:]...)
	bytesRet = append(bytesRet, tx_builder.PackUint32(p.NBits)...)
	bytesRet = append(bytesRet, tx_builder.PackUint64(p.Nonce)...)

	return bytesRet, nil
}
