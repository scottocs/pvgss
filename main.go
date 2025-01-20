package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	// "pvgss/compile/contract"
	"pvgss/compile/contract/Dex"
	"pvgss/utils"

	// "pvgss/crypto/rwdabe"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvgss/bn128"
	// lib "github.com/fentec-project/gofe/abe"
	// "pvgss/crypto/pvgss-sss/sss"
)

type ACJudge struct {
	Props []string `json:"props"`
	ACS   string   `json:"acs"`
}

func G1ToPoint(point *bn128.G1) Dex.DexG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := Dex.DexG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func IntToBig(array []int) []*big.Int {
	bigArray := make([]*big.Int, len(array))
	for i := 0; i < len(array); i++ {
		bigArray[i] = big.NewInt(int64(array[i]))
	}
	return bigArray
}

func G1sToPoints(num int, points []*bn128.G1) []Dex.DexG1Point {
	g1Points := make([]Dex.DexG1Point, num)
	for i := 0; i < num; i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
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

// LSSS test
// func main() {

// 	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Failed to open log file: %v", err)
// 	}
// 	defer file.Close()

// 	log.SetOutput(file)

// 	dex_contract_address := common.HexToAddress("0xC1ECc1ea905149A792bc5Dc0baC45D630F496824")
// 	pveth_contract_address := common.HexToAddress("0xB4FeFEAbBCA91a14352A7f699d65243Fbb3Ce8ea")
// 	pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")
// 	privateKeys := []string{
// 		utils.GetENV("PRIVATE_KEY_1"),
// 		utils.GetENV("PRIVATE_KEY_2"),
// 		utils.GetENV("PRIVATE_KEY_3"),
// 		utils.GetENV("PRIVATE_KEY_4"),
// 		utils.GetENV("PRIVATE_KEY_5"),
// 		utils.GetENV("PRIVATE_KEY_6"),
// 		utils.GetENV("PRIVATE_KEY_7"),
// 		utils.GetENV("PRIVATE_KEY_8"),
// 		utils.GetENV("PRIVATE_KEY_9"),
// 		utils.GetENV("PRIVATE_KEY_10"),
// 	}
// 	// accounts := []common.Address{
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_1")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_2")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_3")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_4")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_5")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_6")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_7")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_8")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_9")),
// 	// 	common.HexToAddress(utils.GetENV("ACCOUNT_10")),
// 	// }

// 	accountNum := 10
// 	allSK, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	//_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	if err != nil {
// 		log.Fatalf("Failed to load accounts: %v", err)
// 	}

// 	client, err := ethclient.Dial("ws://127.0.0.1:8545")
// 	if err != nil {
// 		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
// 	}

// 	dexInstance, _ := Dex.NewDex(dex_contract_address, client)
// 	//pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)

// 	//pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

// 	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

// 	orderId := big.NewInt(0)

// 	for nx := 1; nx < 9; nx++ {
// 		log.Println("test for order", orderId, " with watchers", nx)

// 		//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
// 		// account1Balance, err := dexInstance.Balances(nil, accounts[0], pveth_contract_address)
// 		// if err != nil {
// 		// 	log.Fatalf("Failed to stake eth: %v", err)
// 		// } else {
// 		// 	log.Printf("Balance of %s for token %s: %s\n", accounts[0].Hex(), pveth_contract_address.Hex(), account1Balance.String())
// 		// }

// 		auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		amountSell, ok := new(big.Int).SetString("10000000000000000", 10) //0.01 PVETH
// 		if !ok {
// 			log.Fatalf("Failed to set amount")
// 		}
// 		amountBuy, ok := new(big.Int).SetString("30000000000000000000", 10) //30 PVUDST
// 		if !ok {
// 			log.Fatalf("Failed to set amount")
// 		}
// 		tx1, _ := dexInstance.CreateOrder(auth1, pveth_contract_address, amountSell, pvusdt_contract_address, amountBuy)
// 		_, _ = bind.WaitMined(context.Background(), client, tx1)
// 		receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
// 		log.Println("On-chain CreateOrder Gas cost = ", receipt1.GasUsed)

// 		//account2 accept order :  call acceptOrder(uint256 orderId)
// 		auth2 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)))
// 		receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
// 		log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

// 		// //1. PVGSSSetup
// 		// nx := 2       // the number of Watchers   account 3, account 4, account 5 now
// 		t := 2        // the threshold of Watchers
// 		num := nx + 2 // the number of leaf nodes

// 		// Of-chain: construct the access control structure
// 		root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
// 		A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
// 		B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
// 		X := gss.NewNode(false, nx, t, big.NewInt(int64(3)))
// 		root.Children = []*gss.Node{A, B, X}
// 		Xp := make([]*gss.Node, nx)
// 		for i := 0; i < nx; i++ {
// 			Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
// 		}
// 		X.Children = Xp

// 		// Generate secret values randomly
// 		secret, _ := rand.Int(rand.Reader, bn128.Order)

// 		//set active account num
// 		accountNum = num

// 		SK := make([]*big.Int, accountNum)
// 		PK1 := make([]*bn128.G1, accountNum)
// 		PK2 := make([]*bn128.G2, accountNum)

// 		for i := 0; i < accountNum; i++ {
// 			SK[i] = allSK[i]
// 			PK1[i] = allPK1[i]
// 			PK2[i] = allPK2[i]
// 		}

// 		// 2. PVGSSShare
// 		lC, lprfs, _ := pvgss_lsss.PVGSSShare(secret, root, PK1)

// 		// 3. PVGSSVerify
// 		I0 := make([]int, 2)
// 		I0[0] = 0
// 		I0[1] = 1
// 		// Off-chain
// 		_, _ = pvgss_lsss.PVGSSVerify(lC, lprfs, root, PK1, I0)

// 		// fmt.Println("Off-chain Shares verfication result = ", lisShareValid)

// 		// 4. PVGSSPreRecon
// 		ldecShares := make([]*bn128.G1, num)
// 		for i := 0; i < num; i++ {
// 			ldecShares[i], _ = pvgss_lsss.PVGSSPreRecon(lC[i], SK[i])
// 		}

// 		// 5. PVGSSKeyVrf
// 		// Off-chain
// 		lofchainIsKeyValid := make([]bool, num)
// 		for i := 0; i < num; i++ {
// 			lofchainIsKeyValid[i], _ = pvgss_lsss.PVGSSKeyVrf(lC[i], ldecShares[i], PK2[i])
// 		}

// 		// On-chain  account2 call swap1 in t1
// 		log.Println("account2 Lswap1 in t1")

// 		auth21 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx21, _ := dexInstance.LUploadProof(auth21, G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
// 		receipt, _ := bind.WaitMined(context.Background(), client, tx21)
// 		log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

// 		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx10, _ := dexInstance.Lswap1(auth10, orderId, G1sToPoints(num, lC), G1sToPoints(num, PK1), lsss.Convert(root), IntToBig(I0))
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx10)
// 		log.Println("On-chain LSwap1 Gas cost = ", receipt.GasUsed)

// 		//account1 call swap1 and swap2 in t1

// 		//swap1
// 		log.Println("account1 Lswap1 in t1")
// 		auth := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ := dexInstance.LUploadProof(auth, G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Lswap1(auth, orderId, G1sToPoints(num, lC), G1sToPoints(num, PK1), lsss.Convert(root), IntToBig(I0))
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain LSwap1 Gas cost = ", receipt.GasUsed)

// 		//swap2
// 		log.Println("account1 swap2 in t1")
// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(ldecShares[0]))
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

// 		log.Println("sleep until t2")
// 		time.Sleep(31 * time.Second)

// 		//account1 complain in t1-t2
// 		log.Println("account1 complain in t2")
// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Complain(auth, orderId)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

// 		//account2 call swap2 in t1
// 		// fmt.Println("account2 swap2 in t1")
// 		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		// tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(decShares[1]))
// 		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		// fmt.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

// 		// //enough watchers submit share in t2 if complain
// 		// fmt.Println("enough watchers submit share in t2")
// 		// for i := 2; i < 5; i++ {
// 		// 	auth := utils.Transact(client, privateKeys[i], big.NewInt(0))
// 		// 	tx, _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[i]))
// 		// 	receipt, _ := bind.WaitMined(context.Background(), client, tx)
// 		// 	fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)
// 		// }

// 		// //not enough watchers submit share in t2 if complain
// 		// fmt.Println("enough watchers submit share in t2")
// 		// auth := utils.Transact(client, privateKeys[2], big.NewInt(0))
// 		// tx , _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[2]))
// 		// receipt, _ := bind.WaitMined(context.Background(), client, tx)
// 		// fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)

// 		//after t2 determine
// 		//sleep t2 time
// 		log.Println("sleep until t2 end")
// 		time.Sleep(1 * time.Minute)

// 		log.Println("account2 determine after t2")
// 		auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx, _ = dexInstance.Determine(auth, orderId)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Determine Gas cost = ", receipt.GasUsed)

// 		orderId.Add(orderId, big.NewInt(1))
// 	}
// 	// value, err = pvusdtInstance.BalanceOf(nil, accounts[0])
// 	// if err != nil {
// 	// 	log.Fatalf("Failed to get balance: %v", err)
// 	// } else {
// 	// 	fmt.Println("value:", value)
// 	// }
// }

// SSS test
// func main() {

// 	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Failed to open log file: %v", err)
// 	}
// 	defer file.Close()

// 	log.SetOutput(file)

// 	dex_contract_address := common.HexToAddress("0x7A752F433Fbac25b96ab7708022488bBf9c35C82")
// 	pveth_contract_address := common.HexToAddress("0xB4FeFEAbBCA91a14352A7f699d65243Fbb3Ce8ea")
// 	pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")
// 	privateKeys := []string{
// 		utils.GetENV("PRIVATE_KEY_1"),
// 		utils.GetENV("PRIVATE_KEY_2"),
// 		utils.GetENV("PRIVATE_KEY_3"),
// 		utils.GetENV("PRIVATE_KEY_4"),
// 		utils.GetENV("PRIVATE_KEY_5"),
// 		utils.GetENV("PRIVATE_KEY_6"),
// 		utils.GetENV("PRIVATE_KEY_7"),
// 		utils.GetENV("PRIVATE_KEY_8"),
// 		utils.GetENV("PRIVATE_KEY_9"),
// 		utils.GetENV("PRIVATE_KEY_10"),
// 	}
// 	accounts := []common.Address{
// 		common.HexToAddress(utils.GetENV("ACCOUNT_1")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_2")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_3")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_4")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_5")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_6")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_7")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_8")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_9")),
// 		common.HexToAddress(utils.GetENV("ACCOUNT_10")),
// 	}

// 	accountNum := 10
// 	allSK, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	//_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	if err != nil {
// 		log.Fatalf("Failed to load accounts: %v", err)
// 	}

// 	client, err := ethclient.Dial("ws://127.0.0.1:8545")
// 	if err != nil {
// 		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
// 	}

// 	dexInstance, _ := Dex.NewDex(dex_contract_address, client)

// 	//pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)

// 	//pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

// 	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

// 	orderId := big.NewInt(0)

// 	for nx := 1; nx < 9; nx++ {
// 		log.Println("test for order", orderId, " with watchers", nx)

// 		//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
// 		account1Balance, err := dexInstance.Balances(nil, accounts[0], pveth_contract_address)
// 		if err != nil {
// 			log.Fatalf("Failed to stake eth: %v", err)
// 		} else {
// 			log.Printf("Balance of %s for token %s: %s\n", accounts[0].Hex(), pveth_contract_address.Hex(), account1Balance.String())
// 		}

// 		auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		amountSell, ok := new(big.Int).SetString("10000000000000000", 10) //0.01 PVETH
// 		if !ok {
// 			log.Fatalf("Failed to set amount")
// 		}
// 		amountBuy, ok := new(big.Int).SetString("30000000000000000000", 10) //30 PVUDST
// 		if !ok {
// 			log.Fatalf("Failed to set amount")
// 		}
// 		tx1, _ := dexInstance.CreateOrder(auth1, pveth_contract_address, amountSell, pvusdt_contract_address, amountBuy)
// 		_, _ = bind.WaitMined(context.Background(), client, tx1)
// 		receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
// 		log.Println("On-chain CreateOrder Gas cost = ", receipt1.GasUsed)

// 		//account2 accept order :  call acceptOrder(uint256 orderId)
// 		auth2 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)))
// 		receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
// 		log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

// 		// //1. PVGSSSetup
// 		// nx := 2       // the number of Watchers   account 3, account 4, account 5 now
// 		t := 2        // the threshold of Watchers
// 		num := nx + 2 // the number of leaf nodes

// 		// Of-chain: construct the access control structure
// 		root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
// 		A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
// 		B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
// 		X := gss.NewNode(false, nx, t, big.NewInt(int64(3)))
// 		root.Children = []*gss.Node{A, B, X}
// 		Xp := make([]*gss.Node, nx)
// 		for i := 0; i < nx; i++ {
// 			Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
// 		}
// 		X.Children = Xp

// 		// Generate secret values randomly
// 		secret, _ := rand.Int(rand.Reader, bn128.Order)

// 		//set active account num
// 		accountNum = num

// 		SK := make([]*big.Int, accountNum)
// 		PK1 := make([]*bn128.G1, accountNum)
// 		PK2 := make([]*bn128.G2, accountNum)

// 		for i := 0; i < accountNum; i++ {
// 			SK[i] = allSK[i]
// 			PK1[i] = allPK1[i]
// 			PK2[i] = allPK2[i]
// 		}

// 		// 2. PVGSSShare
// 		C, prfs, _ := pvgss_sss.PVGSSShare(secret, root, PK1)

// 		// Of-chain: construct paths that satisfy the access control structure
// 		// Case1: A and B
// 		path1 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
// 		path1.Children = []*gss.Node{A, B}

// 		// On-chain: construct the access control structure
// 		// On-chain: construct paths that satisfy the access control structure
// 		auth1_1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx1_1, _ := dexInstance.CreatePath(auth1_1, big.NewInt(int64(nx)), big.NewInt(int64(t)), big.NewInt(1))
// 		_, _ = bind.WaitMined(context.Background(), client, tx1_1)

// 		VrfQ := make([]*big.Int, 2)
// 		VrfQ[0] = prfs.Shatarry[0]
// 		VrfQ[1] = prfs.Shatarry[1]

// 		// 3. PVGSSVerify
// 		// Off-chain
// 		isShareValid, _ := pvgss_sss.PVGSSVerify(C, prfs, root, PK1, path1)

// 		log.Println("Of-chain Verfication result = ", isShareValid)

// 		// 4. PVGSSPreRecon
// 		decShares := make([]*bn128.G1, num)
// 		for i := 0; i < num; i++ {
// 			decShares[i], _ = pvgss_sss.PVGSSPreRecon(C[i], SK[i])
// 		}

// 		// 5. PVGSSKeyVrf
// 		// Off-chain
// 		ofchainIsKeyValid := make([]bool, num)
// 		for i := 0; i < num; i++ {
// 			ofchainIsKeyValid[i], _ = pvgss_sss.PVGSSKeyVrf(C[i], decShares[i], PK2[i])
// 		}
// 		log.Println("Of-chain KeyVerification result = ", ofchainIsKeyValid)

// 		// On-chain  account2 call swap1 in t1
// 		log.Println("account2 swap1 in t1")
// 		auth := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx, _ := dexInstance.UploadProof(auth, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
// 		_, _ = bind.WaitMined(context.Background(), client, tx)

// 		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx10, _ := dexInstance.Swap1(auth10, orderId, G1sToPoints(num, C), G1sToPoints(num, PK1), big.NewInt(0), VrfQ, big.NewInt(0))
// 		receipt, _ := bind.WaitMined(context.Background(), client, tx10)
// 		log.Println("On-chain Swap1 Gas cost = ", receipt.GasUsed)

// 		onchainIsShareValid, _ := dexInstance.GetVerifyResult(&bind.CallOpts{})
// 		log.Println("On-chain Verfication result = ", onchainIsShareValid)

// 		//account1 call swap1 and swap2 in t1

// 		//swap1
// 		log.Println("account1 swap1 in t1")
// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.UploadProof(auth, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain UploadProof Gas cost = ", receipt.GasUsed)

// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Swap1(auth, orderId, G1sToPoints(num, C), G1sToPoints(num, PK1), big.NewInt(0), VrfQ, big.NewInt(0))
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Swap1 Gas cost = ", receipt.GasUsed)

// 		//swap2
// 		log.Println("account1 swap2 in t1")
// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(decShares[0]))
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

// 		log.Println("sleep until t2")
// 		time.Sleep(31 * time.Second)

// 		//account1 complain in t1-t2
// 		log.Println("account1 complain in t2")
// 		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
// 		tx, _ = dexInstance.Complain(auth, orderId)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

// 		//account2 call swap2 in t1
// 		// fmt.Println("account2 swap2 in t1")
// 		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		// tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(decShares[1]))
// 		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		// fmt.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

// 		// //enough watchers submit share in t2 if complain
// 		// fmt.Println("enough watchers submit share in t2")
// 		// for i := 2; i < 5; i++ {
// 		// 	auth := utils.Transact(client, privateKeys[i], big.NewInt(0))
// 		// 	tx, _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[i]))
// 		// 	receipt, _ := bind.WaitMined(context.Background(), client, tx)
// 		// 	fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)
// 		// }

// 		// //not enough watchers submit share in t2 if complain
// 		// fmt.Println("enough watchers submit share in t2")
// 		// auth := utils.Transact(client, privateKeys[2], big.NewInt(0))
// 		// tx , _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[2]))
// 		// receipt, _ := bind.WaitMined(context.Background(), client, tx)
// 		// fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)

// 		//after t2 determine
// 		//sleep t2 time
// 		log.Println("sleep until t2 end")
// 		time.Sleep(1 * time.Minute)

// 		log.Println("account2 determine after t2")
// 		auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
// 		tx, _ = dexInstance.Determine(auth, orderId)
// 		receipt, _ = bind.WaitMined(context.Background(), client, tx)
// 		log.Println("On-chain Determine Gas cost = ", receipt.GasUsed)

// 		orderId.Add(orderId, big.NewInt(1))
// 	}
// 	// value, err = pvusdtInstance.BalanceOf(nil, accounts[0])
// 	// if err != nil {
// 	// 	log.Fatalf("Failed to get balance: %v", err)
// 	// } else {
// 	// 	fmt.Println("value:", value)
// 	// }
// }

// deploy new dex contract and register and deposit
// func main() {
// 	pveth_contract_address := common.HexToAddress("0xB4FeFEAbBCA91a14352A7f699d65243Fbb3Ce8ea")
// 	pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")
// 	privateKeys := []string{
// 		utils.GetENV("PRIVATE_KEY_1"),
// 		utils.GetENV("PRIVATE_KEY_2"),
// 		utils.GetENV("PRIVATE_KEY_3"),
// 		utils.GetENV("PRIVATE_KEY_4"),
// 		utils.GetENV("PRIVATE_KEY_5"),
// 		utils.GetENV("PRIVATE_KEY_6"),
// 		utils.GetENV("PRIVATE_KEY_7"),
// 		utils.GetENV("PRIVATE_KEY_8"),
// 		utils.GetENV("PRIVATE_KEY_9"),
// 		utils.GetENV("PRIVATE_KEY_10"),
// 	}

// 	client, err := ethclient.Dial("ws://127.0.0.1:8545")
// 	if err != nil {
// 		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
// 	}

// 	deployTX := utils.Transact(client, privateKeys[3], big.NewInt(0))
// 	dex_contract_address, _ := utils.Deploy(client, "Dex", deployTX)

// 	accountNum := 10
// 	_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	//_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
// 	if err != nil {
// 		log.Fatalf("Failed to load accounts: %v", err)
// 	}

// 	dexInstance, _ := Dex.NewDex(dex_contract_address, client)
// 	pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)
// 	pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

// 	//register account1 to account10
// 	for i, privateKey := range privateKeys {
// 		auth := utils.Transact(client, privateKey, big.NewInt(0))
// 		tx, _ := dexInstance.Register(auth, G1ToPoint(allPK1[i]), G2ToPoint(allPK2[i]))
// 		receipt, _ := bind.WaitMined(context.Background(), client, tx)
// 		fmt.Println("On-chain Register Gas cost = ", receipt.GasUsed)
// 	}

// 	//stake 2 eth  account1 to account10 (account 3-10 as watcher)
// 	for i, privateKey := range privateKeys {
// 		auth := utils.Transact(client, privateKey, big.NewInt(9000000000000000000))
// 		if i > 1 {
// 			_, err := dexInstance.StakeETH(auth, true)
// 			if err != nil {
// 				log.Fatalf("Failed to stake eth: %v", err)
// 			}
// 		} else {
// 			_, err := dexInstance.StakeETH(auth, false)
// 			if err != nil {
// 				log.Fatalf("Failed to stake eth: %v", err)
// 			}
// 		}
// 	}

// 	//account1 deposit 10 PVETH   account2 deposit 10000 PVUSDT

// 	auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 	amount, ok := new(big.Int).SetString("10000000000000000000", 10) // 10 * 1e18
// 	if !ok {
// 		log.Fatalf("Failed to set amount")
// 	}
// 	_, err = pvethInstance.Approve(auth1, dex_contract_address, amount)
// 	if err != nil {
// 		log.Fatalf("Failed to approve: %v", err)
// 	}

// 	auth2 := utils.Transact(client, privateKeys[0], big.NewInt(0))
// 	dexInstance.Deposit(auth2, pveth_contract_address, amount)

// 	auth3 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 	amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
// 	if !ok {
// 		log.Fatalf("Failed to set amount")
// 	}
// 	_, err = pvusdtInstance.Approve(auth3, dex_contract_address, amount)
// 	if err != nil {
// 		log.Fatalf("Failed to approve: %v", err)
// 	}

// 	auth4 := utils.Transact(client, privateKeys[1], big.NewInt(0))
// 	amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
// 	if !ok {
// 		log.Fatalf("Failed to set amount")
// 	}
// 	dexInstance.Deposit(auth4, pvusdt_contract_address, amount)
// }

// func LoadAccountsFromEnv(accountNum int) ([]*big.Int, []*bn128.G1, []*bn128.G2, error) {
// 	err := godotenv.Load(".env")
// 	if err != nil {
// 		return nil, nil, nil, fmt.Errorf("failed to load .env file: %v", err)
// 	}

// 	envVars, err := godotenv.Read(".env")
// 	if err != nil {
// 		envVars = make(map[string]string)
// 	}

// 	allSK := make([]*big.Int, accountNum)
// 	allPK1 := make([]*bn128.G1, accountNum)
// 	allPK2 := make([]*bn128.G2, accountNum)

// 	for i := 0; i < accountNum; i++ {
// 		envVarPrefix := fmt.Sprintf("ACCOUNT_%d", i+1)

// 		skHex := envVars[envVarPrefix+"_SK"]
// 		skBytes, err := hex.DecodeString(skHex)
// 		if err != nil {
// 			return nil, nil, nil, fmt.Errorf("failed to decode SK hex string: %v", err)
// 		}
// 		allSK[i] = new(big.Int).SetBytes(skBytes)

// 		pk1Hex := envVars[envVarPrefix+"_PK1"]
// 		pk1Bytes, err := hex.DecodeString(pk1Hex)
// 		if err != nil {
// 			return nil, nil, nil, fmt.Errorf("failed to decode PK1 hex string: %v", err)
// 		}
// 		allPK1[i] = new(bn128.G1)
// 		_, err = allPK1[i].Unmarshal(pk1Bytes)
// 		if err != nil {
// 			return nil, nil, nil, fmt.Errorf("failed to unmarshal PK1: %v", err)
// 		}

// 		pk2Hex := envVars[envVarPrefix+"_PK2"]
// 		pk2Bytes, err := hex.DecodeString(pk2Hex)
// 		if err != nil {
// 			return nil, nil, nil, fmt.Errorf("failed to decode PK2 hex string: %v", err)
// 		}
// 		allPK2[i] = new(bn128.G2)
// 		_, err = allPK2[i].Unmarshal(pk2Bytes)
// 		if err != nil {
// 			return nil, nil, nil, fmt.Errorf("failed to unmarshal PK2: %v", err)
// 		}
// 	}

// 	return allSK, allPK1, allPK2, nil
// }

//deploy to sepolia

func main() {
	client, err := ethclient.Dial("https://sepolia.infura.io/v3/b7c50bb656a8449a8f22383f8931ab1e")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	blockNumber, err := client.BlockNumber(context.Background())
	if err != nil {
		log.Fatalf("Failed to get block number: %v", err)
	}

	log.Printf("Connected to Sepolia testnet. Latest block number: %d\n", blockNumber)
	privateKey := "3912ab7d5ed19e73e31dbebefd26fa3434895ee527aacdc2195f8b24f717ca5e"

	deployTX := utils.Transact(client, privateKey, big.NewInt(0))

	dex_contract_address, tx := utils.Deploy(client, "Dex", deployTX)

	receipt, _ := bind.WaitMined(context.Background(), client, tx)
	fmt.Println("depoly Gas cost = ", receipt.GasUsed)

	log.Printf("Contract deployed at address: %s\n", dex_contract_address.Hex())
	log.Printf("Transaction hash: %s\n", tx.Hash().Hex())
}
