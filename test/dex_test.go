package test

import (
	"context"
	"crypto/rand"
	"log"
	"math/big"
	"os"
	bn128 "pvgss/bn128"
	"pvgss/compile/contract/Dex"
	"pvgss/crypto/dleq"
	"pvgss/crypto/lssspvgss"
	"pvgss/crypto/lssspvgss/lsss"
	"pvgss/crypto/node"
	"pvgss/crypto/ssspvgss"
	"pvgss/utils"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestDexGasLSSS(t *testing.T) {
	if os.Getenv("PVGSS_RUN_INTEGRATION") != "1" {
		t.Skip("set PVGSS_RUN_INTEGRATION=1 and start a local Ethereum node to run this integration benchmark")
	}
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()
	log.SetOutput(file)

	// dex_contract_address := common.HexToAddress("0xC1ECc1ea905149A792bc5Dc0baC45D630F496824")
	// pveth_contract_address := common.HexToAddress("0xB4FeFEAbBCA91a14352A7f699d65243Fbb3Ce8ea")
	// pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")

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

	allSK := make([]*big.Int, accountNum)
	allPK1 := make([]*bn128.G1, accountNum)
	for i := 0; i < accountNum; i++ {
		allSK[i], allPK1[i] = ssspvgss.PVGSSSetup()
	}
	if err != nil {
		log.Fatalf("Failed to load accounts: %v", err)
	}

	dex_contract_address, pveth_contract_address, pvusdt_contract_address, _ := utils.DeployAndRegister(allPK1)
	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	dexInstance, _ := Dex.NewDex(dex_contract_address, client)
	//pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)

	//pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

	orderId := big.NewInt(0)

	for nx := 1; nx < 11; nx++ {
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
		_, _ = bind.WaitMined(context.Background(), client, tx1)
		// log.Println("On-chain CreateOrder Gas cost = ", receipt1.GasUsed)

		//account2 accept order :  call acceptOrder(uint256 orderId)
		auth2 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)), big.NewInt(1))
		_, _ = bind.WaitMined(context.Background(), client, tx2)
		// log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

		// //1. PVGSSSetup
		// nx := 2       // the number of Watchers
		t := 1        // the threshold of Watchers
		num := nx + 2 // the number of leaf nodes

		// Off-chain: construct the access control structure
		root := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
		A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		X := node.NewNode(false, nx, t, big.NewInt(int64(3)))
		root.Children = []*node.Node{A, B, X}
		Xp := make([]*node.Node, nx)
		for i := 0; i < nx; i++ {
			Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
		}
		X.Children = Xp

		// Generate secret values randomly
		secret, _ := rand.Int(rand.Reader, bn128.Order)

		//set active account num
		accountNum = num

		SK := make([]*big.Int, accountNum)
		PK1 := make([]*bn128.G1, accountNum)

		for i := 0; i < accountNum; i++ {
			SK[i] = allSK[i]
			PK1[i] = allPK1[i]
		}

		matrix := lsss.Convert(root)
		// 2. PVGSSShare
		lC, lprfs, _ := lssspvgss.PVGSSShare(secret, root, PK1)

		// 3. PVGSSVerify
		// A and B
		I0 := make([]int, 2)
		I0[0] = 0
		I0[1] = 1
		weights0, _ := lsss.ReconstructionWeightsForRows(matrix, I0)

		// A and Watchers
		I00 := make([]int, 1+t)
		I00[0] = 0
		for i := 0; i < t; i++ {
			I00[i+1] = i + 2
		}
		weights, _ := lsss.ReconstructionWeightsForRows(matrix, I00)
		_, _ = lssspvgss.PVGSSVerify(lC, lprfs, root, PK1)

		//fmt.Println("Off-chain Shares verification result = ", lisShareValid)
		authPath := utils.Transact(client, privateKeys[0], big.NewInt(0))
		txPath, _ := dexInstance.CreatePath(authPath, big.NewInt(int64(nx)), big.NewInt(int64(t)), big.NewInt(4))
		_, _ = bind.WaitMined(context.Background(), client, txPath)

		// 4. PVGSSPreRecon
		ldecShares := make([]*bn128.G1, num)
		lproofs := make([]*dleq.DLEQProof, num)
		for i := 0; i < num; i++ {
			ldecShares[i], lproofs[i], _ = lssspvgss.PVGSSPreRecon(lC[i], SK[i])
		}

		// 5. PVGSSKeyVrf
		// Off-chain
		loffchainIsKeyValid := make([]bool, num)
		for i := 0; i < num; i++ {
			loffchainIsKeyValid[i], _ = lssspvgss.PVGSSKeyVrf(lC[i], ldecShares[i], PK1[i], lproofs[i])
		}

		// On-chain account2 commits in t1.
		log.Println("account2 commitLSSS in t1")

		// auth21 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx21, _ := dexInstance.LUploadProof(auth21, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
		// receipt, _ := bind.WaitMined(context.Background(), client, tx21)
		// log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx10, _ := dexInstance.CommitLSSS(auth10, orderId, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry, utils.G1sToPoints(num, lC), utils.G1sToPoints(num, PK1), weights0, weights, utils.IntToBig(I0), utils.IntToBig(I00))
		receipt, _ := bind.WaitMined(context.Background(), client, tx10)
		log.Println("On-chain CommitLSSS Gas cost = ", receipt.GasUsed)

		// Account1 commits and opens in t1.

		// commit
		log.Println("account1 commitLSSS in t1")
		// auth := utils.Transact(client, privateKeys[0], big.NewInt(0))
		// tx, _ := dexInstance.LUploadProof(auth, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// log.Println("On-chain LUploadProof Gas cost = ", receipt.GasUsed)

		auth := utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ := dexInstance.CommitLSSS(auth, orderId, utils.G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry, utils.G1sToPoints(num, lC), utils.G1sToPoints(num, PK1), weights0, weights, utils.IntToBig(I0), utils.IntToBig(I00))
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain CommitLSSS Gas cost = ", receipt.GasUsed)

		// open
		log.Println("account1 open in t1")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Open(auth, orderId, utils.G1ToPoint(ldecShares[0]), utils.G1ToPoint(lproofs[0].C1), utils.G1ToPoint(lproofs[0].C2), lproofs[0].Challenge, lproofs[0].Response)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Open Gas cost = ", receipt.GasUsed)

		log.Println("sleep until t2")
		time.Sleep(31 * time.Second)

		//account1 complain in t1-t2
		log.Println("account1 complain in t2")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Complain(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

		// Account2 opens in t1.
		// fmt.Println("account2 open in t1")
		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx, _ = dexInstance.Open(auth, orderId, G1ToPoint(decShares[1]))
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// fmt.Println("On-chain Open Gas cost = ", receipt.GasUsed)

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
	if os.Getenv("PVGSS_RUN_INTEGRATION") != "1" {
		t.Skip("set PVGSS_RUN_INTEGRATION=1 and start a local Ethereum node to run this integration benchmark")
	}
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	log.SetOutput(file)

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
		utils.GetENV("PRIVATE_KEY_11"),
		utils.GetENV("PRIVATE_KEY_12"),
		utils.GetENV("PRIVATE_KEY_13"),
		utils.GetENV("PRIVATE_KEY_14"),
		utils.GetENV("PRIVATE_KEY_15"),
		utils.GetENV("PRIVATE_KEY_16"),
		utils.GetENV("PRIVATE_KEY_17"),
		utils.GetENV("PRIVATE_KEY_18"),
		utils.GetENV("PRIVATE_KEY_19"),
		utils.GetENV("PRIVATE_KEY_20"),
	}

	accountNum := 20

	allSK := make([]*big.Int, accountNum)
	allPK1 := make([]*bn128.G1, accountNum)
	for i := 0; i < accountNum; i++ {
		allSK[i], allPK1[i] = ssspvgss.PVGSSSetup()
	}
	if err != nil {
		log.Fatalf("Failed to load accounts: %v", err)
	}

	dex_contract_address, pveth_contract_address, pvusdt_contract_address, _ := utils.DeployAndRegister(allPK1)

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	dexInstance, _ := Dex.NewDex(dex_contract_address, client)

	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

	orderId := big.NewInt(0)

	for nx := 1; nx < 19; nx++ {
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
		tx2, _ := dexInstance.AcceptOrder(auth2, orderId, big.NewInt(int64(nx)), big.NewInt(1))
		receipt2, _ := bind.WaitMined(context.Background(), client, tx2)
		log.Println("On-chain AcceptOrder Gas cost = ", receipt2.GasUsed)

		// //1. PVGSSSetup
		// nx := 2       // the number of Watchers   account 3, account 4, account 5 now
		t := 1        // the threshold of Watchers
		num := nx + 2 // the number of leaf nodes

		// Off-chain: construct the access control structure
		root := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
		A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		X := node.NewNode(false, nx, t, big.NewInt(int64(3)))
		root.Children = []*node.Node{A, B, X}
		Xp := make([]*node.Node, nx)
		for i := 0; i < nx; i++ {
			Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
		}
		X.Children = Xp

		// Generate secret values randomly
		secret, _ := rand.Int(rand.Reader, bn128.Order)

		//set active account num
		accountNum = num

		SK := make([]*big.Int, accountNum)
		PK1 := make([]*bn128.G1, accountNum)

		for i := 0; i < accountNum; i++ {
			SK[i] = allSK[i]
			PK1[i] = allPK1[i]
		}

		// 2. PVGSSShare
		C, prfs, _ := ssspvgss.PVGSSShare(secret, root, PK1)

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
		isShareValid, _ := ssspvgss.PVGSSVerify(C, prfs, root, PK1)

		log.Println("Off-chain Verification result = ", isShareValid)

		// 4. PVGSSPreRecon
		decShares := make([]*bn128.G1, num)
		proofs := make([]*dleq.DLEQProof, num)
		for i := 0; i < num; i++ {
			decShares[i], proofs[i], _ = ssspvgss.PVGSSPreRecon(C[i], SK[i])
		}

		// 5. PVGSSKeyVrf
		// Off-chain
		offchainIsKeyValid := make([]bool, num)
		for i := 0; i < num; i++ {
			offchainIsKeyValid[i], _ = ssspvgss.PVGSSKeyVrf(C[i], decShares[i], PK1[i], proofs[i])
		}
		log.Println("Off-chain KeyVerification result = ", offchainIsKeyValid)

		// On-chain account2 commits in t1.
		log.Println("account2 commit in t1")
		// auth := utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx, _ := dexInstance.UploadProof(auth, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
		// _, _ = bind.WaitMined(context.Background(), client, tx)

		auth10 := utils.Transact(client, privateKeys[1], big.NewInt(0))
		tx10, _ := dexInstance.Commit(auth10, orderId, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry, utils.G1sToPoints(num, C), utils.G1sToPoints(num, PK1), VrfQ)
		receipt, _ := bind.WaitMined(context.Background(), client, tx10)
		log.Println("On-chain Commit Gas cost = ", receipt.GasUsed)

		// Account1 commits and opens in t1.

		// commit
		log.Println("account1 commit in t1")
		// auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		// tx, _ = dexInstance.UploadProof(auth, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// log.Println("On-chain UploadProof Gas cost = ", receipt.GasUsed)

		auth := utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ := dexInstance.Commit(auth, orderId, utils.G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry, utils.G1sToPoints(num, C), utils.G1sToPoints(num, PK1), VrfQ)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Commit Gas cost = ", receipt.GasUsed)

		// open
		log.Println("account1 open in t1")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Open(auth, orderId, utils.G1ToPoint(decShares[0]), utils.G1ToPoint(proofs[0].C1), utils.G1ToPoint(proofs[0].C2), proofs[0].Challenge, proofs[0].Response)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Open Gas cost = ", receipt.GasUsed)

		log.Println("sleep until t2")
		time.Sleep(31 * time.Second)

		//account1 complain in t1-t2
		log.Println("account1 complain in t2")
		auth = utils.Transact(client, privateKeys[0], big.NewInt(0))
		tx, _ = dexInstance.Complain(auth, orderId)
		receipt, _ = bind.WaitMined(context.Background(), client, tx)
		log.Println("On-chain Complain Gas cost = ", receipt.GasUsed)

		// Account2 opens in t1.
		// fmt.Println("account2 open in t1")
		// auth = utils.Transact(client, privateKeys[1], big.NewInt(0))
		// tx, _ = dexInstance.Open(auth, orderId, G1ToPoint(decShares[1]))
		// receipt, _ = bind.WaitMined(context.Background(), client, tx)
		// fmt.Println("On-chain Open Gas cost = ", receipt.GasUsed)

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
