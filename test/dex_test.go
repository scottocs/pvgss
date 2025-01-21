package test

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	bn128 "pvgss/bn128"
	"pvgss/compile/contract/Dex"
	"pvgss/crypto/pvgss-lsss2/lsss"
	"pvgss/crypto/pvgss-lsss2/pvgss_lsss"
	"pvgss/crypto/pvgss-sss/gss"
	"pvgss/crypto/pvgss-sss/pvgss_sss"
	"pvgss/utils"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestDexGasLSSS(t *testing.T) {
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()
	log.SetOutput(file)

	// dex_contract_address := common.HexToAddress("0xC1ECc1ea905149A792bc5Dc0baC45D630F496824")
	// pveth_contract_address := common.HexToAddress("0xB4FeFEAbBCA91a14352A7f699d65243Fbb3Ce8ea")
	// pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")

	dex_contract_address, pveth_contract_address, pvusdt_contract_address, _ := utils.DepolyAndRegister()

	privateKeys := []string{
		utils.GetENV("PRIVATE_KEY_1"),
		utils.GetENV("PRIVATE_KEY_2"),
		utils.GetENV("PRIVATE_KEY_3"),
		utils.GetENV("PRIVATE_KEY_4"),
		utils.GetENV("PRIVATE_KEY_5"),
		utils.GetENV("PRIVATE_KEY_6"),
		utils.GetENV("PRIVATE_KEY_7"),
		utils.GetENV("PRIVATE_KEY_8"),
		utils.GetENV("PRIVATE_KEY_9"),
		utils.GetENV("PRIVATE_KEY_10"),
	}
	accountNum := 10
	allSK, allPK1, allPK2, err := utils.LoadAccountsFromEnv(accountNum)
	//_, allPK1, allPK2, err := LoadAccountsFromEnv(accountNum)
	if err != nil {
		log.Fatalf("Failed to load accounts: %v", err)
	}

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	dexInstance, _ := Dex.NewDex(dex_contract_address, client)
	//pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)

	//pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

	orderId := big.NewInt(0)

	for nx := 1; nx < 9; nx++ {
		log.Println("test for order", orderId, " with watchers", nx)

		//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
		auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
		amountSell, ok := new(big.Int).SetString("10000000000000000", 10) //0.01 PVETH
		if !ok {
			log.Fatalf("Failed to set amount")
		}
		amountBuy, ok := new(big.Int).SetString("30000000000000000000", 10) //30 PVUDST
		if !ok {
			log.Fatalf("Failed to set amount")
		}
		tx1, _ := dexInstance.CreateOrder(auth1, pveth_contract_address, amountSell, pvusdt_contract_address, amountBuy)
		_, _ = bind.WaitMined(context.Background(), client, tx1)
		receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
		log.Println("On-chain CreateOrder Gas cost = ", receipt1.GasUsed)

		//account2 accept order :  call acceptOrder(uint256 orderId)
		auth2 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)))
		receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
		log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

		// //1. PVGSSSetup
		// nx := 2       // the number of Watchers
		t := 1        // the threshold of Watchers
		num := nx + 2 // the number of leaf nodes

		// Of-chain: construct the access control structure
		root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
		A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
		B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
		X := gss.NewNode(false, nx, t, big.NewInt(int64(3)))
		root.Children = []*gss.Node{A, B, X}
		Xp := make([]*gss.Node, nx)
		for i := 0; i < nx; i++ {
			Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
		}
		X.Children = Xp

		// Generate secret values randomly
		secret, _ := rand.Int(rand.Reader, bn128.Order)

		//set active account num
		accountNum = num

		SK := make([]*big.Int, accountNum)
		PK1 := make([]*bn128.G1, accountNum)
		PK2 := make([]*bn128.G2, accountNum)

		for i := 0; i < accountNum; i++ {
			SK[i] = allSK[i]
			PK1[i] = allPK1[i]
			PK2[i] = allPK2[i]
		}

		matrix := lsss.Convert(root)
		// 2. PVGSSShare
		lC, lprfs, _ := pvgss_lsss.PVGSSShare(secret, matrix, PK1)

		// 3. PVGSSVerify
		// A and B
		I0 := make([]int, 2)
		I0[0] = 0
		I0[1] = 1
		rows0 := len(I0)
		recMatrix0 := make([][]*big.Int, rows0)
		for i := 0; i < rows0; i++ {
			recMatrix0[i] = matrix[I0[i]][:rows0]
		}
		invRecMatrix0, _ := lsss.GaussJordanInverse(recMatrix0)

		// A and Watchers
		I00 := make([]int, 1+t)
		I00[0] = 0
		for i := 0; i < t; i++ {
			I00[i+1] = i + 2
		}
		rows := len(I00)
		recMatrix := make([][]*big.Int, rows)
		for i := 0; i < rows; i++ {
			recMatrix[i] = matrix[I00[i]][:rows]
		}
		invRecMatrix, _ := lsss.GaussJordanInverse(recMatrix)
		lisShareValid, _ := pvgss_lsss.PVGSSVerify(lC, lprfs, invRecMatrix0, invRecMatrix, PK1, I0, I00)

		fmt.Println("Off-chain Shares verfication result = ", lisShareValid)

		// 4. PVGSSPreRecon
		ldecShares := make([]*bn128.G1, num)
		for i := 0; i < num; i++ {
			ldecShares[i], _ = pvgss_lsss.PVGSSPreRecon(lC[i], SK[i])
		}

		// 5. PVGSSKeyVrf
		// Off-chain
		lofchainIsKeyValid := make([]bool, num)
		for i := 0; i < num; i++ {
			lofchainIsKeyValid[i], _ = pvgss_lsss.PVGSSKeyVrf(lC[i], ldecShares[i], PK2[i])
		}

		// On-chain  account2 call swap1 in t1
		log.Println("account2 Lswap1 in t1")

		auth21 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx21, _ := dexInstance.LUploadProof(auth21, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
		receipt, _ := bind.WaitMined(context.Background(), client, tx21)
		log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx10, _ := dexInstance.Lswap1(auth10, orderId, utils.G1sToPoints(num, lC), utils.G1sToPoints(num, PK1), invRecMatrix0, invRecMatrix, utils.IntToBig(I0), utils.IntToBig(I00))
		receipt, _ = bind.WaitMined(context.Background(), client, tx10)
		log.Println("On-chain LSwap1 Gas cost = ", receipt.GasUsed)

		//account1 call swap1 and swap2 in t1

		//swap1
		log.Println("account1 Lswap1 in t1")
		auth := utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ := dexInstance.LUploadProof(auth, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Lswap1(auth, orderId, utils.G1sToPoints(num, lC), utils.G1sToPoints(num, PK1), invRecMatrix0, invRecMatrix, utils.IntToBig(I0), utils.IntToBig(I00))
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain LSwap1 Gas cost = ", receipt.GasUsed)

		//swap2
		log.Println("account1 swap2 in t1")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Swap2(auth, orderId, utils.G1ToPoint(ldecShares[0]))
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

		log.Println("sleep until t2")
		time.Sleep(31 * time.Second)

		//account1 complain in t1-t2
		log.Println("account1 complain in t2")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Complain(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

		//account2 call swap2 in t1
		// fmt.Println("account2 swap2 in t1")
		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(decShares[1]))
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// fmt.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

		// //enough watchers submit share in t2 if complain
		// fmt.Println("enough watchers submit share in t2")
		// for i := 2; i < 5; i++ {
		// 	auth := utils.Transact(client, privateKeys[i], big.NewInt(0))
		// 	tx, _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[i]))
		// 	receipt, _ := bind.WaitMined(context.Background(), client, tx)
		// 	fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)
		// }

		//sleep t2 time
		log.Println("sleep until t2 end")
		time.Sleep(1 * time.Minute)

		log.Println("account2 determine after t2")
		auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx, _ = dexInstance.Determine(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Determine Gas cost = ", receipt.GasUsed)

		orderId.Add(orderId, big.NewInt(1))
	}
}

func TestDexGasSSS(t *testing.T) {
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	log.SetOutput(file)

	dex_contract_address, pveth_contract_address, pvusdt_contract_address, _ := utils.DepolyAndRegister()
	privateKeys := []string{
		utils.GetENV("PRIVATE_KEY_1"),
		utils.GetENV("PRIVATE_KEY_2"),
		utils.GetENV("PRIVATE_KEY_3"),
		utils.GetENV("PRIVATE_KEY_4"),
		utils.GetENV("PRIVATE_KEY_5"),
		utils.GetENV("PRIVATE_KEY_6"),
		utils.GetENV("PRIVATE_KEY_7"),
		utils.GetENV("PRIVATE_KEY_8"),
		utils.GetENV("PRIVATE_KEY_9"),
		utils.GetENV("PRIVATE_KEY_10"),
	}

	accountNum := 10
	allSK, allPK1, allPK2, err := utils.LoadAccountsFromEnv(accountNum)
	if err != nil {
		log.Fatalf("Failed to load accounts: %v", err)
	}

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	dexInstance, _ := Dex.NewDex(dex_contract_address, client)

	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

	orderId := big.NewInt(0)

	for nx := 1; nx < 9; nx++ {
		log.Println("test for order", orderId, " with watchers", nx)
		//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
		auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
		amountSell, ok := new(big.Int).SetString("10000000000000000", 10) //0.01 PVETH
		if !ok {
			log.Fatalf("Failed to set amount")
		}
		amountBuy, ok := new(big.Int).SetString("30000000000000000000", 10) //30 PVUDST
		if !ok {
			log.Fatalf("Failed to set amount")
		}
		tx1, _ := dexInstance.CreateOrder(auth1, pveth_contract_address, amountSell, pvusdt_contract_address, amountBuy)
		_, _ = bind.WaitMined(context.Background(), client, tx1)
		receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
		log.Println("On-chain CreateOrder Gas cost = ", receipt1.GasUsed)

		//account2 accept order :  call acceptOrder(uint256 orderId)
		auth2 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)))
		receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
		log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

		// //1. PVGSSSetup
		// nx := 2       // the number of Watchers   account 3, account 4, account 5 now
		t := 1        // the threshold of Watchers
		num := nx + 2 // the number of leaf nodes

		// Of-chain: construct the access control structure
		root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
		A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
		B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
		X := gss.NewNode(false, nx, t, big.NewInt(int64(3)))
		root.Children = []*gss.Node{A, B, X}
		Xp := make([]*gss.Node, nx)
		for i := 0; i < nx; i++ {
			Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
		}
		X.Children = Xp

		// Generate secret values randomly
		secret, _ := rand.Int(rand.Reader, bn128.Order)

		//set active account num
		accountNum = num

		SK := make([]*big.Int, accountNum)
		PK1 := make([]*bn128.G1, accountNum)
		PK2 := make([]*bn128.G2, accountNum)

		for i := 0; i < accountNum; i++ {
			SK[i] = allSK[i]
			PK1[i] = allPK1[i]
			PK2[i] = allPK2[i]
		}

		// 2. PVGSSShare
		C, prfs, _ := pvgss_sss.PVGSSShare(secret, root, PK1)

		// Of-chain: construct paths that satisfy the access control structure
		I := make([]int, nx+2)
		// I[0] = 0
		for i := 0; i < nx+2; i++ {
			I[i] = i
		}

		// On-chain: construct the access control structure
		// On-chain: construct paths that satisfy the access control structure
		// A and B and Watchers
		auth1_1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx1_1, _ := dexInstance.CreatePath(auth1_1, big.NewInt(int64(nx)), big.NewInt(int64(t)), big.NewInt(4))
		_, _ = bind.WaitMined(context.Background(), client, tx1_1)

		VrfQ := make([]*big.Int, 2+t)
		// VrfQ[0] = big.NewInt(1)
		for i := 0; i < t+2; i++ {
			VrfQ[i] = big.NewInt(int64(i))
		}

		// 3. PVGSSVerify
		// Off-chain
		isShareValid, _ := pvgss_sss.PVGSSVerify(C, prfs, root, PK1, root, I)

		log.Println("Of-chain Verfication result = ", isShareValid)

		// 4. PVGSSPreRecon
		decShares := make([]*bn128.G1, num)
		for i := 0; i < num; i++ {
			decShares[i], _ = pvgss_sss.PVGSSPreRecon(C[i], SK[i])
		}

		// 5. PVGSSKeyVrf
		// Off-chain
		ofchainIsKeyValid := make([]bool, num)
		for i := 0; i < num; i++ {
			ofchainIsKeyValid[i], _ = pvgss_sss.PVGSSKeyVrf(C[i], decShares[i], PK2[i])
		}
		log.Println("Of-chain KeyVerification result = ", ofchainIsKeyValid)

		// On-chain  account2 call swap1 in t1
		log.Println("account2 swap1 in t1")
		auth := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx, _ := dexInstance.UploadProof(auth, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
		_, _ = bind.WaitMined(context.Background(), client, tx)

		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx10, _ := dexInstance.Swap1(auth10, orderId, utils.G1sToPoints(num, C), utils.G1sToPoints(num, PK1), VrfQ)
		receipt, _ := bind.WaitMined(context.Background(), client, tx10)
		log.Println("On-chain Swap1 Gas cost = ", receipt.GasUsed)

		onchainIsShareValid, _ := dexInstance.GetVerifyResult(&bind.CallOpts{})
		log.Println("On-chain Verfication result = ", onchainIsShareValid)

		//account1 call swap1 and swap2 in t1

		//swap1
		log.Println("account1 swap1 in t1")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.UploadProof(auth, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain UploadProof Gas cost = ", receipt.GasUsed)

		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Swap1(auth, orderId, utils.G1sToPoints(num, C), utils.G1sToPoints(num, PK1), VrfQ)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Swap1 Gas cost = ", receipt.GasUsed)

		//swap2
		log.Println("account1 swap2 in t1")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Swap2(auth, orderId, utils.G1ToPoint(decShares[0]))
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

		log.Println("sleep until t2")
		time.Sleep(31 * time.Second)

		//account1 complain in t1-t2
		log.Println("account1 complain in t2")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Complain(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

		//account2 call swap2 in t1
		// fmt.Println("account2 swap2 in t1")
		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx, _ = dexInstance.Swap2(auth, orderId, G1ToPoint(decShares[1]))
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// fmt.Println("On-chain Swap2 Gas cost = ", receipt.GasUsed)

		// //enough watchers submit share in t2 if complain
		// fmt.Println("enough watchers submit share in t2")
		// for i := 2; i < 5; i++ {
		// 	auth := utils.Transact(client, privateKeys[i], big.NewInt(0))
		// 	tx, _ := dexInstance.SubmitWatcherShare(auth, orderId, G1ToPoint(decShares[i]))
		// 	receipt, _ := bind.WaitMined(context.Background(), client, tx)
		// 	fmt.Println("On-chain SubmitWatcherShare Gas cost = ", receipt.GasUsed)
		// }

		//sleep t2 time
		log.Println("sleep until t2 end")
		time.Sleep(1 * time.Minute)

		log.Println("account2 determine after t2")
		auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx, _ = dexInstance.Determine(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Determine Gas cost = ", receipt.GasUsed)

		orderId.Add(orderId, big.NewInt(1))
	}
}
