// go与区块链交互需要的函数
package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"pvgss/compile/contract/Dex"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

// deploy contract and obtain abi interface and bin of source code
func Deploy(client *ethclient.Client, contract_name string, auth *bind.TransactOpts) (common.Address, *types.Transaction) {

	abiBytes, err := os.ReadFile("compile/contract/" + contract_name + "/" + contract_name + ".abi")
	if err != nil {
		log.Fatalf("Failed to read ABI file: %v", err)
	}

	bin, err := os.ReadFile("compile/contract/" + contract_name + "/" + contract_name + ".bin")
	if err != nil {
		log.Fatalf("Failed to read BIN file: %v", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	address, tx, _, err := bind.DeployContract(auth, parsedABI, common.FromHex(string(bin)), client)
	if err != nil {
		log.Fatalf("Failed to deploy contract: %v", err)
	}
	fmt.Printf("%s.sol deployed! Address: %s\n", contract_name, address.Hex())
	fmt.Printf("Transaction hash: %s\n", tx.Hash().Hex())
	return address, tx
}

// construct a transaction
func Transact(client *ethclient.Client, privatekey string, value *big.Int) *bind.TransactOpts {
	key, _ := crypto.HexToECDSA(privatekey)
	publicKey := key.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	//gasLimit := uint64(90071992547)
	//gasPrice, err := client.SuggestGasPrice(context.Background())
	//if err != nil {
	//	log.Fatalf("Failed to get gas price: %v", err)
	//}
	chainID, err := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(key, chainID)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = uint64(12719925)        //gasLimit
	auth.GasPrice = big.NewInt(20000000000) //gasPrice
	return auth
}

func GetENV(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Some error occured. Err: %s", err)
	}
	return os.Getenv(key)
}

func randomOperand(operands []string) (string, []string) {
	index := rand.Intn(len(operands))
	operand := operands[index]
	operands = append(operands[:index], operands[index+1:]...)
	return operand, operands
}

func RandomACP(operands []string) string {

	operand1, remainingOperands := randomOperand(operands)
	operands = remainingOperands

	if len(operands) == 0 {
		return operand1
	}
	operand2, remainingOperands := randomOperand(operands)
	operands = remainingOperands

	operator := ""
	if rand.Intn(2) == 0 {
		operator = " AND "
	} else {
		operator = " OR "
	}

	expression := "(" + operand1 + operator + operand2 + ")"

	if len(operands) > 0 {
		expression += operator + RandomACP(operands)
	}

	return expression
}

func ListenToAllEvents(client *ethclient.Client, dexInstance *Dex.Dex, dexAddress common.Address) {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{dexAddress},
	}

	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal("Failed to subscribe to logs:", err)
	}

	fmt.Println("Listening for all events...")

	for {
		select {
		case err := <-sub.Err():
			log.Fatal("Subscription error:", err)
		case vLog := <-logs:
			parseEvent(dexInstance, vLog)
		}
	}
}

func parseEvent(dexInstance *Dex.Dex, vLog types.Log) {

	if event, err := dexInstance.ParseTokensReceived(vLog); err == nil {
		fmt.Printf("TokensReceived Event:\n")
		fmt.Printf("  Token: %s\n", event.Token.Hex())
		fmt.Printf("  From: %s\n", event.From.Hex())
		fmt.Printf("  Amount: %s\n", event.Amount.String())
		return
	}

	if event, err := dexInstance.ParseTokensFrozen(vLog); err == nil {
		fmt.Printf("TokensFrozen Event:\n")
		fmt.Printf("  Token: %s\n", event.Token.Hex())
		fmt.Printf("  From: %s\n", event.From.Hex())
		fmt.Printf("  Amount: %s\n", event.Amount.String())
		fmt.Printf("  Session ID: %s\n", event.SessionId.String())
		return
	}

	if event, err := dexInstance.ParseTokensSwapped(vLog); err == nil {
		fmt.Printf("TokensSwapped Event:\n")
		fmt.Printf("  Token: %s\n", event.Token.Hex())
		fmt.Printf("  From: %s\n", event.From.Hex())
		fmt.Printf("  Amount: %s\n", event.Amount.String())
		fmt.Printf("  Session ID: %s\n", event.SessionId.String())
		return
	}

	if event, err := dexInstance.ParseComplaintFiled(vLog); err == nil {
		fmt.Printf("ComplaintFiled Event:\n")
		fmt.Printf("  Complainer: %s\n", event.Complainer.Hex())
		fmt.Printf("  Session ID: %s\n", event.SessionId.String())
		return
	}

	if event, err := dexInstance.ParseSessionStateUpdated(vLog); err == nil {
		fmt.Printf("SessionStateUpdated Event:\n")
		fmt.Printf("  Session ID: %s\n", event.SessionId.String())
		fmt.Printf("  State: %v\n", event.State)
		return
	}

	if event, err := dexInstance.ParseUserNotified(vLog); err == nil {
		fmt.Printf("UserNotified Event:\n")
		fmt.Printf("  Session ID: %s\n", event.SessionId.String())
		fmt.Printf("  User: %s\n", event.User.Hex())
		return
	}

	if event, err := dexInstance.ParseOrderCreated(vLog); err == nil {
		fmt.Printf("OrderCreated Event:\n")
		fmt.Printf("  Order ID: %s\n", event.OrderId.String())
		fmt.Printf("  Seller: %s\n", event.Seller.Hex())
		fmt.Printf("  Token Sell: %s\n", event.TokenSell.Hex())
		fmt.Printf("  Amount Sell: %s\n", event.AmountSell.String())
		fmt.Printf("  Token Buy: %s\n", event.TokenBuy.Hex())
		fmt.Printf("  Amount Buy: %s\n", event.AmountBuy.String())
		return
	}

	if event, err := dexInstance.ParseIncentivized(vLog); err == nil {
		fmt.Printf("Incentivized Event:\n")
		fmt.Printf("  Exchanger: %s\n", event.Exchanger.Hex())
		fmt.Printf("  Amount: %s\n", event.Amount.String())
		return
	}

	if event, err := dexInstance.ParsePenalized(vLog); err == nil {
		fmt.Printf("Penalized Event:\n")
		fmt.Printf("  Exchanger: %s\n", event.Exchanger.Hex())
		fmt.Printf("  Amount: %s\n", event.Amount.String())
		return
	}

	if event, err := dexInstance.ParseSessionCreated(vLog); err == nil {
		fmt.Printf("SessionCreated Event:\n")
		fmt.Printf("  Order ID: %s\n", event.OrderId.String())
		fmt.Printf("  Seller: %s\n", event.Seller.Hex())
		fmt.Printf("  Buyer: %s\n", event.Buyer.Hex())
		fmt.Printf("  Watchers: %v\n", event.Watchers)
		fmt.Printf("  Expiration1: %s\n", event.Expiration1.String())
		fmt.Printf("  Expiration2: %s\n", event.Expiration2.String())
		return
	}

	fmt.Printf("Unknown Event: %+v\n", vLog)
}
