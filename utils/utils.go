package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	bn128 "pvgss/bn128"
	"pvgss/compile/contract/Dex"
	"pvgss/compile/contract/PVETH"
	"pvgss/compile/contract/PVUSDT"
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

	abiBytes, err := os.ReadFile("../compile/contract/" + contract_name + "/" + contract_name + ".abi")
	if err != nil {
		log.Fatalf("Failed to read ABI file: %v", err)
	}

	bin, err := os.ReadFile("../compile/contract/" + contract_name + "/" + contract_name + ".bin")
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
	chainID, err := client.ChainID(context.Background())
	auth, _ := bind.NewKeyedTransactorWithChainID(key, chainID)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = uint64(900719925)       //gasLimit
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

func LoadAccountsFromEnv(accountNum int) ([]*big.Int, []*bn128.G1, []*bn128.G2, error) {
	err := godotenv.Load(".env")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load .env file: %v", err)
	}

	envVars, err := godotenv.Read(".env")
	if err != nil {
		envVars = make(map[string]string)
	}

	allSK := make([]*big.Int, accountNum)
	allPK1 := make([]*bn128.G1, accountNum)
	allPK2 := make([]*bn128.G2, accountNum)

	for i := 0; i < accountNum; i++ {
		envVarPrefix := fmt.Sprintf("ACCOUNT_%d", i+1)

		skHex := envVars[envVarPrefix+"_SK"]
		skBytes, err := hex.DecodeString(skHex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode SK hex string: %v", err)
		}
		allSK[i] = new(big.Int).SetBytes(skBytes)

		pk1Hex := envVars[envVarPrefix+"_PK1"]
		pk1Bytes, err := hex.DecodeString(pk1Hex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode PK1 hex string: %v", err)
		}
		allPK1[i] = new(bn128.G1)
		_, err = allPK1[i].Unmarshal(pk1Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to unmarshal PK1: %v", err)
		}

		pk2Hex := envVars[envVarPrefix+"_PK2"]
		pk2Bytes, err := hex.DecodeString(pk2Hex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode PK2 hex string: %v", err)
		}
		allPK2[i] = new(bn128.G2)
		_, err = allPK2[i].Unmarshal(pk2Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to unmarshal PK2: %v", err)
		}
	}

	return allSK, allPK1, allPK2, nil
}

func G1ToPoint(point *bn128.G1) Dex.DexG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()

	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := Dex.DexG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1sToPoints(num int, points []*bn128.G1) []Dex.DexG1Point {
	g1Points := make([]Dex.DexG1Point, num)
	for i := 0; i < num; i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
}

func IntToBig(array []int) []*big.Int {
	bigArray := make([]*big.Int, len(array))
	for i := 0; i < len(array); i++ {
		bigArray[i] = big.NewInt(int64(array[i]))
	}
	return bigArray
}

func G2ToPoint(point *bn128.G2) Dex.DexG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := Dex.DexG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

// deploy new dex contract and register and deposit
func DepolyAndRegister() (common.Address, common.Address, common.Address, error) {
	privateKeys := []string{
		GetENV("PRIVATE_KEY_1"),
		GetENV("PRIVATE_KEY_2"),
		GetENV("PRIVATE_KEY_3"),
		GetENV("PRIVATE_KEY_4"),
		GetENV("PRIVATE_KEY_5"),
		GetENV("PRIVATE_KEY_6"),
		GetENV("PRIVATE_KEY_7"),
		GetENV("PRIVATE_KEY_8"),
		GetENV("PRIVATE_KEY_9"),
		GetENV("PRIVATE_KEY_10"),
	}

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	deployTX := Transact(client, privateKeys[3], big.NewInt(0))
	dex_contract_address, _ := Deploy(client, "Dex", deployTX)

	deployTX = Transact(client, privateKeys[0], big.NewInt(0))
	pveth_contract_address, _ := Deploy(client, "PVETH", deployTX)

	deployTX = Transact(client, privateKeys[1], big.NewInt(0))
	pvusdt_contract_address, _ := Deploy(client, "PVUSDT", deployTX)

	accountNum := 10
	_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
	if err != nil {
		log.Fatalf("Failed to load accounts: %v", err)
	}

	dexInstance, _ := Dex.NewDex(dex_contract_address, client)
	pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)
	pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

	//register account1 to account10
	for i, privateKey := range privateKeys {
		auth := Transact(client, privateKey, big.NewInt(0))
		tx, _ := dexInstance.Register(auth, G1ToPoint(allPK1[i]), G2ToPoint(allPK2[i]))
		receipt, _ := bind.WaitMined(context.Background(), client, tx)
		fmt.Println("On-chain Register Gas cost = ", receipt.GasUsed)
	}

	//stake 2 eth  account1 to account10 (account 3-10 as watcher)
	for i, privateKey := range privateKeys {
		auth := Transact(client, privateKey, big.NewInt(9000000000000000000))
		if i > 1 {
			tx, err := dexInstance.StakeETH(auth, true)
			if err != nil {
				log.Fatalf("Failed to stake eth: %v", err)
			}
			receipt, _ := bind.WaitMined(context.Background(), client, tx)
			fmt.Println("On-chain stake Gas cost = ", receipt.GasUsed)
		} else {
			tx, err := dexInstance.StakeETH(auth, false)
			if err != nil {
				log.Fatalf("Failed to stake eth: %v", err)
			}
			receipt, _ := bind.WaitMined(context.Background(), client, tx)
			fmt.Println("On-chain stake Gas cost = ", receipt.GasUsed)
		}
	}

	//account1 deposit 10 PVETH   account2 deposit 10000 PVUSDT

	auth1 := Transact(client, privateKeys[0], big.NewInt(0))
	amount, ok := new(big.Int).SetString("10000000000000000000", 10) // 10 * 1e18
	if !ok {
		log.Fatalf("Failed to set amount")
	}
	_, err = pvethInstance.Approve(auth1, dex_contract_address, amount)
	if err != nil {
		log.Fatalf("Failed to approve: %v", err)
	}

	auth2 := Transact(client, privateKeys[0], big.NewInt(0))
	tx, _ := dexInstance.Deposit(auth2, pveth_contract_address, amount)
	receipt, _ := bind.WaitMined(context.Background(), client, tx)
	fmt.Println("On-chain Deposit Gas cost = ", receipt.GasUsed)

	auth3 := Transact(client, privateKeys[1], big.NewInt(0))
	amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
	if !ok {
		log.Fatalf("Failed to set amount")
	}
	_, err = pvusdtInstance.Approve(auth3, dex_contract_address, amount)
	if err != nil {
		log.Fatalf("Failed to approve: %v", err)
	}

	auth4 := Transact(client, privateKeys[1], big.NewInt(0))
	amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
	if !ok {
		log.Fatalf("Failed to set amount")
	}
	dexInstance.Deposit(auth4, pvusdt_contract_address, amount)

	return dex_contract_address, pveth_contract_address, pvusdt_contract_address, nil
}
