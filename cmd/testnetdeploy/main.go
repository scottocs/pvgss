package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	Dex "pvgss/compile/contract/Dex"
	PVETH "pvgss/compile/contract/PVETH"
	PVUSDT "pvgss/compile/contract/PVUSDT"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

const sepoliaChainID int64 = 11155111

type contractDeployment struct {
	Address         common.Address `json:"address"`
	TransactionHash common.Hash    `json:"transaction_hash"`
	BlockNumber     uint64         `json:"block_number"`
	GasUsed         uint64         `json:"gas_used"`
}

type deploymentRecord struct {
	Network    string                        `json:"network"`
	ChainID    string                        `json:"chain_id"`
	Deployer   common.Address                `json:"deployer"`
	DeployedAt time.Time                     `json:"deployed_at"`
	Contracts  map[string]contractDeployment `json:"contracts"`
}

func main() {
	_ = godotenv.Load(".env.testnet")

	rpcURL := flag.String("rpc", os.Getenv("SEPOLIA_RPC_URL"), "Sepolia HTTPS/WSS JSON-RPC endpoint")
	outPath := flag.String("out", "deployments/sepolia.json", "deployment record path")
	broadcast := flag.Bool("broadcast", false, "broadcast deployment transactions after preflight checks")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall RPC and mining timeout")
	flag.Parse()

	keyHex := os.Getenv("TESTNET_DEPLOYER_PRIVATE_KEY")
	if strings.TrimSpace(*rpcURL) == "" {
		fatal(errors.New("missing Sepolia RPC endpoint: set SEPOLIA_RPC_URL or pass -rpc"))
	}
	if strings.TrimSpace(keyHex) == "" || keyHex == "REPLACE_ME" {
		fatal(errors.New("missing testnet deployer key: set TESTNET_DEPLOYER_PRIVATE_KEY"))
	}

	key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(keyHex), "0x"))
	if err != nil {
		fatal(fmt.Errorf("invalid TESTNET_DEPLOYER_PRIVATE_KEY: %w", err))
	}
	from := addressOf(key)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatal(fmt.Errorf("connect to RPC: %w", err))
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		fatal(fmt.Errorf("read chain ID: %w", err))
	}
	if chainID.Cmp(big.NewInt(sepoliaChainID)) != 0 {
		fatal(fmt.Errorf("refusing deployment: connected to chain ID %s, expected Sepolia (%d)", chainID, sepoliaChainID))
	}

	balance, err := client.BalanceAt(ctx, from, nil)
	if err != nil {
		fatal(fmt.Errorf("read deployer balance: %w", err))
	}
	pendingNonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		fatal(fmt.Errorf("read pending nonce: %w", err))
	}

	bytecodes := []struct {
		name string
		data []byte
	}{
		{"Dex", common.FromHex(Dex.DexBin)},
		{"PVETH", common.FromHex(PVETH.PVETHBin)},
		{"PVUSDT", common.FromHex(PVUSDT.PVUSDTBin)},
	}
	var totalGas uint64
	for _, contract := range bytecodes {
		gas, estimateErr := client.EstimateGas(ctx, ethereum.CallMsg{From: from, Data: contract.data})
		if estimateErr != nil {
			fatal(fmt.Errorf("estimate %s deployment (the contract may exceed a network limit): %w", contract.name, estimateErr))
		}
		totalGas += gas
		fmt.Printf("preflight %-6s creation_bytes=%d estimated_gas=%d\n", contract.name, len(contract.data), gas)
	}

	maxFeePerGas, err := conservativeMaxFeePerGas(ctx, client)
	if err != nil {
		fatal(err)
	}
	worstCaseCost := new(big.Int).Mul(new(big.Int).SetUint64(totalGas), maxFeePerGas)
	fmt.Printf("network=sepolia chain_id=%s deployer=%s nonce=%d\n", chainID, from.Hex(), pendingNonce)
	fmt.Printf("balance=%s ETH estimated_max_cost=%s ETH\n", weiToETH(balance), weiToETH(worstCaseCost))
	if balance.Cmp(worstCaseCost) < 0 {
		fatal(fmt.Errorf("insufficient Sepolia ETH: have %s ETH, estimated maximum deployment cost is %s ETH", weiToETH(balance), weiToETH(worstCaseCost)))
	}
	if !*broadcast {
		fmt.Println("preflight passed; rerun with -broadcast to deploy Dex, PVETH, and PVUSDT")
		return
	}

	record := deploymentRecord{
		Network:    "sepolia",
		ChainID:    chainID.String(),
		Deployer:   from,
		DeployedAt: time.Now().UTC(),
		Contracts:  make(map[string]contractDeployment, 3),
	}

	auth := func() *bind.TransactOpts {
		opts, authErr := bind.NewKeyedTransactorWithChainID(key, chainID)
		if authErr != nil {
			fatal(fmt.Errorf("create transaction signer: %w", authErr))
		}
		opts.Context = ctx
		return opts
	}

	dexAddress, dexTx, _, err := Dex.DeployDex(auth(), client)
	if err != nil {
		fatal(fmt.Errorf("broadcast Dex deployment: %w", err))
	}
	record.Contracts["Dex"] = waitAndVerify(ctx, client, "Dex", dexAddress, dexTx)

	pvethAddress, pvethTx, _, err := PVETH.DeployPVETH(auth(), client)
	if err != nil {
		fatal(fmt.Errorf("broadcast PVETH deployment: %w", err))
	}
	record.Contracts["PVETH"] = waitAndVerify(ctx, client, "PVETH", pvethAddress, pvethTx)

	pvusdtAddress, pvusdtTx, _, err := PVUSDT.DeployPVUSDT(auth(), client)
	if err != nil {
		fatal(fmt.Errorf("broadcast PVUSDT deployment: %w", err))
	}
	record.Contracts["PVUSDT"] = waitAndVerify(ctx, client, "PVUSDT", pvusdtAddress, pvusdtTx)

	if err := writeRecord(*outPath, record); err != nil {
		fatal(err)
	}
	fmt.Printf("deployment record written to %s\n", *outPath)
}

func addressOf(key *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(key.PublicKey)
}

func conservativeMaxFeePerGas(ctx context.Context, client *ethclient.Client) (*big.Int, error) {
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("read latest block header: %w", err)
	}
	if header.BaseFee == nil {
		price, priceErr := client.SuggestGasPrice(ctx)
		if priceErr != nil {
			return nil, fmt.Errorf("suggest legacy gas price: %w", priceErr)
		}
		return price, nil
	}
	tip, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("suggest priority fee: %w", err)
	}
	return new(big.Int).Add(new(big.Int).Mul(header.BaseFee, big.NewInt(2)), tip), nil
}

func waitAndVerify(ctx context.Context, client *ethclient.Client, name string, address common.Address, tx *types.Transaction) contractDeployment {
	fmt.Printf("broadcast %-6s tx=%s predicted_address=%s\n", name, tx.Hash().Hex(), address.Hex())
	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		fatal(fmt.Errorf("wait for %s deployment: %w", name, err))
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		fatal(fmt.Errorf("%s deployment reverted: %s", name, tx.Hash().Hex()))
	}
	code, err := client.CodeAt(ctx, address, receipt.BlockNumber)
	if err != nil {
		fatal(fmt.Errorf("verify %s bytecode: %w", name, err))
	}
	if len(code) == 0 {
		fatal(fmt.Errorf("%s deployment has no code at %s", name, address.Hex()))
	}
	fmt.Printf("mined     %-6s block=%s gas=%d runtime_bytes=%d address=%s\n", name, receipt.BlockNumber, receipt.GasUsed, len(code), address.Hex())
	return contractDeployment{
		Address:         address,
		TransactionHash: tx.Hash(),
		BlockNumber:     receipt.BlockNumber.Uint64(),
		GasUsed:         receipt.GasUsed,
	}
}

func writeRecord(path string, record deploymentRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode deployment record: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create deployment directory: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write deployment record: %w", err)
	}
	return nil
}

func weiToETH(wei *big.Int) string {
	value := new(big.Float).SetPrec(256).SetInt(wei)
	value.Quo(value, new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	return value.Text('f', 8)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
