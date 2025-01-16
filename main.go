package main

import (
	"fmt"
	"log"
	"math/big"

	// "pvgss/compile/contract"
	"pvgss/compile/contract/Dex"
	"pvgss/compile/contract/PVETH"
	"pvgss/compile/contract/PVUSDT"
	"pvgss/crypto/pvgss-sss/pvgss_sss"

	// "pvgss/crypto/rwdabe"
	"pvgss/utils"

	"github.com/ethereum/go-ethereum/common"
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

func main() {
	dex_contract_address := common.HexToAddress("0xE073caaf07365048A79292761f91EaA6BD72cAcE")
	pveth_contract_address := common.HexToAddress("0x1ffb519eee5aac2c95994df195c0e636a9f55610")
	pvusdt_contract_address := common.HexToAddress("0x7621eea52693Fb18022BD36d8C772F8D59CceE61")
	// privateKeys := []string{
	// 	utils.GetENV("PRIVATE_KEY_1"),
	// 	utils.GetENV("PRIVATE_KEY_2"),
	// 	utils.GetENV("PRIVATE_KEY_3"),
	// 	utils.GetENV("PRIVATE_KEY_4"),
	// 	utils.GetENV("PRIVATE_KEY_5"),
	// 	utils.GetENV("PRIVATE_KEY_6"),
	// 	utils.GetENV("PRIVATE_KEY_7"),
	// 	utils.GetENV("PRIVATE_KEY_8"),
	// 	utils.GetENV("PRIVATE_KEY_9"),
	// 	utils.GetENV("PRIVATE_KEY_10"),
	// }

	// Generate secret values randomly
	// secret, _ := rand.Int(rand.Reader, bn128.Order)

	num := 10
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = pvgss_sss.PVGSSSetup()
	}

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v, %v", err, client)
	}

	//depoly contract dex by account1
	// privatekey1 := utils.GetENV("PRIVATE_KEY_1")
	// deployTX := utils.Transact(client, privatekey1, big.NewInt(0))
	// address, _ := utils.Deploy(client, "Dex", deployTX)

	// deploy ERC20 token PVETH by account1
	// privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	// deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	// address, _ := utils.Deploy(client, "PVETH", deployTX)

	// deploy ERC20 token PVUSDT by account2
	// privatekey2 := utils.GetENV("PRIVATE_KEY_2")

	// deployTX := utils.Transact(client, privatekey2, big.NewInt(0))

	// address, _ := utils.Deploy(client, "PVUSDT", deployTX)
	dexInstance, _ := Dex.NewDex(dex_contract_address, client)

	pvethInstance, _ := PVETH.NewPVETH(pveth_contract_address, client)

	pvusdtInstance, _ := PVUSDT.NewPVUSDT(pvusdt_contract_address, client)

	// privatekey1 := utils.GetENV("PRIVATE_KEY_1")
	// auth1 := utils.Transact(client, privatekey1, big.NewInt(0))

	value, err := pvethInstance.BalanceOf(nil, dex_contract_address)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	} else {
		fmt.Println("value of dex_contract:", value)
	}

	value, err = pvusdtInstance.BalanceOf(nil, dex_contract_address)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	} else {
		fmt.Println("value of dex_contract:", value)
	}

	go utils.ListenToAllEvents(client, dexInstance, dex_contract_address)

	//register account1 to account10
	// for i, privateKey := range privateKeys {
	// 	auth := utils.Transact(client, privateKey, big.NewInt(0))
	// 	tx, _ := dexInstance.Register(auth, G1ToPoint(PK1[i]), G2ToPoint(PK2[i]))
	// 	receipt, _ := bind.WaitMined(context.Background(), client, tx)
	// 	fmt.Println("On-chain Register Gas cost = ", receipt.GasUsed)
	// }

	//stake 2 eth  account1 to account10 (account 3-10 as watcher)
	// for i, privateKey := range privateKeys {
	// 	auth := utils.Transact(client, privateKey, big.NewInt(2000000000000000000))
	// 	if i > 2 {
	// 		_, err := dexInstance.StakeETH(auth, false)
	// 		if err != nil {
	// 			log.Fatalf("Failed to stake eth: %v", err)
	// 		}
	// 	} else {
	// 		_, err := dexInstance.StakeETH(auth, true)
	// 		if err != nil {
	// 			log.Fatalf("Failed to stake eth: %v", err)
	// 		}
	// 	}
	// }

	//account1 deposit 10 PVETH   account2 deposit 10000 PVUSDT

	// auth1 := utils.Transact(client, privateKeys[0], big.NewInt(0))
	// amount, ok := new(big.Int).SetString("10000000000000000000", 10) // 10 * 1e18
	// if !ok {
	// 	log.Fatalf("Failed to set amount")
	// }
	// _, err = pvethInstance.Approve(auth1, dex_contract_address, amount)
	// if err != nil {
	// 	log.Fatalf("Failed to approve: %v", err)
	// }

	// auth2 := utils.Transact(client, privateKeys[0], big.NewInt(0))
	// dexInstance.Deposit(auth2, pveth_contract_address, amount)

	// auth3 := utils.Transact(client, privateKeys[1], big.NewInt(0))
	// amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
	// if !ok {
	// 	log.Fatalf("Failed to set amount")
	// }
	// _, err = pvusdtInstance.Approve(auth3, dex_contract_address, amount)
	// if err != nil {
	// 	log.Fatalf("Failed to approve: %v", err)
	// }

	// auth4 := utils.Transact(client, privateKeys[1], big.NewInt(0))
	// amount, ok = new(big.Int).SetString("10000000000000000000000", 10) // 10000 * 1e18
	// if !ok {
	// 	log.Fatalf("Failed to set amount")
	// }
	// dexInstance.Deposit(auth4, pvusdt_contract_address, amount)

	//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
	//account2 accept order :  call acceptOrder(uint256 orderId)

}

// func main() {

// 	contract_name := "Dex"

// 	client, err := ethclient.Dial("http://127.0.0.1:8545")
// 	if err != nil {
// 		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
// 	}

// 	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

// 	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

// 	address, _ := utils.Deploy(client, contract_name, deployTX)

// 	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)

// 	//==== PVGSS-SSS Test ====

// 	// 1. PVGSSSetup
// 	nx := 10       // the number of Watchers
// 	tx := nx/2 + 1 // the threshold of Watchers
// 	num := nx + 2  // the number of leaf nodes

// 	// Of-chain: construct the access control structure
// 	root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
// 	A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
// 	B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
// 	X := gss.NewNode(false, nx, tx, big.NewInt(int64(3)))
// 	root.Children = []*gss.Node{A, B, X}
// 	Xp := make([]*gss.Node, nx)
// 	for i := 0; i < nx; i++ {
// 		Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
// 	}
// 	X.Children = Xp

// 	// Generate secret values randomly
// 	secret, _ := rand.Int(rand.Reader, bn128.Order)

// 	SK := make([]*big.Int, num)
// 	PK1 := make([]*bn128.G1, num)
// 	PK2 := make([]*bn128.G2, num)
// 	for i := 0; i < num; i++ {
// 		SK[i], PK1[i], PK2[i] = pvgss_sss.PVGSSSetup()
// 	}

// 	// 2. PVGSSShare
// 	C, prfs, _ := pvgss_sss.PVGSSShare(secret, root, PK1)

// 	// Of-chain: construct paths that satisfy the access control structure
// 	// Case1: A and B
// 	path1 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
// 	path1.Children = []*gss.Node{A, B}

// 	// Case2: A and Watchers
// 	path2 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
// 	path2.Children = []*gss.Node{A, X}

// 	// Case3: B and Watchers
// 	path3 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
// 	path3.Children = []*gss.Node{B, X}

// 	// On-chain: construct the access control structure
// 	// On-chain: construct paths that satisfy the access control structure
// 	// Creat on-chain path
// 	// creat root
// 	auth1 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx1, _ := ctc.CreateNode(auth1, big.NewInt(int64(0)), big.NewInt(int64(0)), false, big.NewInt(int64(2)), big.NewInt(int64(2)))
// 	_, _ = bind.WaitMined(context.Background(), client, tx1)
// 	// creat A
// 	auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx2, _ := ctc.CreateNode(auth2, big.NewInt(int64(0)), big.NewInt(int64(1)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
// 	_, _ = bind.WaitMined(context.Background(), client, tx2)
// 	// creat B
// 	auth3 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx3, _ := ctc.CreateNode(auth3, big.NewInt(int64(0)), big.NewInt(int64(2)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
// 	_, _ = bind.WaitMined(context.Background(), client, tx3)
// 	// creat tx of P1,P2...,Pnx
// 	auth4 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx4, _ := ctc.CreateNode(auth4, big.NewInt(int64(0)), big.NewInt(int64(3)), false, big.NewInt(int64(nx)), big.NewInt(int64(tx)))
// 	_, _ = bind.WaitMined(context.Background(), client, tx4)
// 	// creat Watchers: P1,P2,...Pnx
// 	childID := make([]*big.Int, nx)
// 	for i := 0; i < nx; i++ {
// 		childID[i] = big.NewInt(int64(i + 1))
// 		authx := utils.Transact(client, privatekey1, big.NewInt(0))
// 		txx, _ := ctc.CreateNode(authx, big.NewInt(int64(3)), big.NewInt(int64(i+1)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
// 		_, _ = bind.WaitMined(context.Background(), client, txx)
// 	}
// 	auth5 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx5, _ := ctc.AddChild(auth5, big.NewInt(int64(3)), childID)
// 	_, _ = bind.WaitMined(context.Background(), client, tx5)
// 	// A and B
// 	// Case1: A and B
// 	rootChild1 := make([]*big.Int, 2)
// 	rootChild1[0] = big.NewInt(int64(1))
// 	rootChild1[1] = big.NewInt(int64(2))
// 	auth6_1 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx6_1, _ := ctc.AddChild(auth6_1, big.NewInt(int64(0)), rootChild1)
// 	_, _ = bind.WaitMined(context.Background(), client, tx6_1)

// 	VrfQ := make([]*big.Int, 2)
// 	VrfQ[0] = prfs.Shatarry[0]
// 	VrfQ[1] = prfs.Shatarry[1]

// 	// A and Watchers
// 	// Case2: A and X
// 	// rootChild2 := make([]*big.Int, 2)
// 	// rootChild2[0] = big.NewInt(int64(1))
// 	// rootChild2[1] = big.NewInt(int64(3))
// 	// auth6_2 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	// tx6_2, _ := ctc.AddChild(auth6_2, big.NewInt(int64(0)), rootChild2)
// 	// _, _ = bind.WaitMined(context.Background(), client, tx6_2)

// 	// VrfQ := make([]*big.Int, tx+1)
// 	// VrfQ[0] = prfs.Shatarry[0]
// 	// for i := 1; i < tx+1; i++ {
// 	// 	VrfQ[i] = prfs.Shatarry[i+1]
// 	// }

// 	// B and Watchers
// 	// Case3: B and X
// 	// rootChild3 := make([]*big.Int, 2)
// 	// rootChild3[0] = big.NewInt(int64(2))
// 	// rootChild3[1] = big.NewInt(int64(3))
// 	// auth6_3 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	// tx6_3, _ := ctc.AddChild(auth6_3, big.NewInt(int64(0)), rootChild3)
// 	// _, _ = bind.WaitMined(context.Background(), client, tx6_3)

// 	// 3. PVGSSVerify
// 	// Off-chain
// 	isShareValid, _ := pvgss_sss.PVGSSVerify(C, prfs, root, PK1, path1)

// 	fmt.Println("Of-chain Verfication result = ", isShareValid)

// 	// On-chain
// 	auth8 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx8, _ := ctc.UploadProof(auth8, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
// 	_, _ = bind.WaitMined(context.Background(), client, tx8)

// 	auth9 := utils.Transact(client, privatekey1, big.NewInt(0))
// 	tx9, _ := ctc.PVGSSVerify(auth9, G1sToPoints(num, C), G1sToPoints(num, PK1), big.NewInt(0), VrfQ, big.NewInt(0))
// 	receipt9, _ := bind.WaitMined(context.Background(), client, tx9)
// 	fmt.Println("On-chain Verification Gas cost = ", receipt9.GasUsed)

// 	onchainIsShareValid, _ := ctc.GetVerifyResult(&bind.CallOpts{})
// 	fmt.Println("On-chain Verfication result = ", onchainIsShareValid)

// 	// 4. PVGSSPreRecon
// 	decShares := make([]*bn128.G1, num)
// 	for i := 0; i < num; i++ {
// 		decShares[i], _ = pvgss_sss.PVGSSPreRecon(C[i], SK[i])
// 	}

// 	// 5. PVGSSKeyVrf
// 	// Off-chain
// 	ofchainIsKeyValid := make([]bool, num)
// 	for i := 0; i < num; i++ {
// 		ofchainIsKeyValid[i], _ = pvgss_sss.PVGSSKeyVrf(C[i], decShares[i], PK2[i])
// 	}
// 	fmt.Println("Of-chain KeyVerification result = ", ofchainIsKeyValid)

// 	// On-chain
// 	var allgasused uint64
// 	for i := 0; i < num; i++ {
// 		auth11 := utils.Transact(client, privatekey1, big.NewInt(0))
// 		tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(C[i]), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(new(bn128.G2).ScalarBaseMult(big.NewInt(1))))
// 		// tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(decShares[i].Neg(decShares[i])), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(PK2[i]))
// 		receipt11, _ := bind.WaitMined(context.Background(), client, tx11)
// 		allgasused += receipt11.GasUsed
// 	}
// 	onchainIsKeyValid, _ := ctc.GetKeyVrfResult(&bind.CallOpts{})
// 	// fmt.Println("order = ", bn128.Order)
// 	fmt.Println("On-chain KeyVerification result = ", onchainIsKeyValid)
// 	fmt.Println("On-chain KeyVerification result = ", allgasused)

// }
