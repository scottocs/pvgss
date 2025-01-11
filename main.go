package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"pvgss/compile/contract"

	// "pvgss/crypto/rwdabe"
	"pvgss/utils"
	"strconv"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvgss/bn128"

	// lib "github.com/fentec-project/gofe/abe"
	// "pvgss/crypto/pvgss-sss/sss"
	"pvgss/crypto/pvgss-sss/gss"
	"pvgss/crypto/pvgss-sss/pvgss_sss"
)

type ACJudge struct {
	Props []string `json:"props"`
	ACS   string   `json:"acs"`
}

func G1ToPoint(point *bn128.G1) contract.DexG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := contract.DexG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1sToPoints(num int, points []*bn128.G1) []contract.DexG1Point {
	g1Points := make([]contract.DexG1Point, num)
	for i := 0; i < num; i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
}

func G2ToPoint(point *bn128.G2) contract.DexG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.DexG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

func generateACPStr(n int) *ACJudge {

	attrs := make([]string, n)
	for i := 1; i < n+1; i++ {
		attrs[i-1] = "auth" + strconv.Itoa(i) + ":at1"
		//fmt.Println(strconv.Itoa(i))
	}

	acp := utils.RandomACP(attrs)
	//fmt.Println(acp, attrs)
	return &ACJudge{ACS: acp, Props: attrs}
}

func main() {

	contract_name := "Dex"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, deployTX)

	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)

	//==== PVGSS-SSS Test ====

	// 1. PVGSSSetup
	nx := 10       // the number of Watchers
	tx := nx/2 + 1 // the threshold of Watchers
	num := nx + 2  // the number of leaf nodes

	// Of-chain: construct the access control structure
	root := gss.NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := gss.NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := gss.NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := gss.NewNode(false, nx, tx, big.NewInt(int64(3)))
	root.Children = []*gss.Node{A, B, X}
	Xp := make([]*gss.Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = gss.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	// Generate secret values randomly
	secret, _ := rand.Int(rand.Reader, bn128.Order)

	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = pvgss_sss.PVGSSSetup()
	}

	// 2. PVGSSShare
	C, prfs, _ := pvgss_sss.PVGSSShare(secret, root, PK1)

	// Of-chain: construct paths that satisfy the access control structure
	// Case1: A and B
	path1 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*gss.Node{A, B}

	// Case2: A and Watchers
	path2 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path2.Children = []*gss.Node{A, X}

	// Case3: B and Watchers
	path3 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path3.Children = []*gss.Node{B, X}

	// On-chain: construct the access control structure
	// On-chain: construct paths that satisfy the access control structure
	// Creat on-chain path
	// creat root
	auth1 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx1, _ := ctc.CreateNode(auth1, big.NewInt(int64(0)), big.NewInt(int64(0)), false, big.NewInt(int64(2)), big.NewInt(int64(2)))
	_, _ = bind.WaitMined(context.Background(), client, tx1)
	// creat A
	auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx2, _ := ctc.CreateNode(auth2, big.NewInt(int64(0)), big.NewInt(int64(1)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
	_, _ = bind.WaitMined(context.Background(), client, tx2)
	// creat B
	auth3 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx3, _ := ctc.CreateNode(auth3, big.NewInt(int64(0)), big.NewInt(int64(2)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
	_, _ = bind.WaitMined(context.Background(), client, tx3)
	// creat tx of P1,P2...,Pnx
	auth4 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx4, _ := ctc.CreateNode(auth4, big.NewInt(int64(0)), big.NewInt(int64(3)), false, big.NewInt(int64(nx)), big.NewInt(int64(tx)))
	_, _ = bind.WaitMined(context.Background(), client, tx4)
	// creat Watchers: P1,P2,...Pnx
	childID := make([]*big.Int, nx)
	for i := 0; i < nx; i++ {
		childID[i] = big.NewInt(int64(i + 1))
		authx := utils.Transact(client, privatekey1, big.NewInt(0))
		txx, _ := ctc.CreateNode(authx, big.NewInt(int64(3)), big.NewInt(int64(i+1)), true, big.NewInt(int64(0)), big.NewInt(int64(1)))
		_, _ = bind.WaitMined(context.Background(), client, txx)
	}
	auth5 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx5, _ := ctc.AddChild(auth5, big.NewInt(int64(3)), childID)
	_, _ = bind.WaitMined(context.Background(), client, tx5)
	// A and B
	// Case1: A and B
	rootChild1 := make([]*big.Int, 2)
	rootChild1[0] = big.NewInt(int64(1))
	rootChild1[1] = big.NewInt(int64(2))
	auth6_1 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx6_1, _ := ctc.AddChild(auth6_1, big.NewInt(int64(0)), rootChild1)
	_, _ = bind.WaitMined(context.Background(), client, tx6_1)

	VrfQ := make([]*big.Int, 2)
	VrfQ[0] = prfs.Shatarry[0]
	VrfQ[1] = prfs.Shatarry[1]

	// A and Watchers
	// Case2: A and X
	// rootChild2 := make([]*big.Int, 2)
	// rootChild2[0] = big.NewInt(int64(1))
	// rootChild2[1] = big.NewInt(int64(3))
	// auth6_2 := utils.Transact(client, privatekey1, big.NewInt(0))
	// tx6_2, _ := ctc.AddChild(auth6_2, big.NewInt(int64(0)), rootChild2)
	// _, _ = bind.WaitMined(context.Background(), client, tx6_2)

	// VrfQ := make([]*big.Int, tx+1)
	// VrfQ[0] = prfs.Shatarry[0]
	// for i := 1; i < tx+1; i++ {
	// 	VrfQ[i] = prfs.Shatarry[i+1]
	// }

	// B and Watchers
	// Case3: B and X
	// rootChild3 := make([]*big.Int, 2)
	// rootChild3[0] = big.NewInt(int64(2))
	// rootChild3[1] = big.NewInt(int64(3))
	// auth6_3 := utils.Transact(client, privatekey1, big.NewInt(0))
	// tx6_3, _ := ctc.AddChild(auth6_3, big.NewInt(int64(0)), rootChild3)
	// _, _ = bind.WaitMined(context.Background(), client, tx6_3)

	// 3. PVGSSVerify
	// Off-chain
	isShareValid, _ := pvgss_sss.PVGSSVerify(C, prfs, root, PK1, path1)

	fmt.Println("Of-chain Verfication result = ", isShareValid)

	// On-chain
	auth8 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx8, _ := ctc.UploadProof(auth8, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
	_, _ = bind.WaitMined(context.Background(), client, tx8)

	auth9 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx9, _ := ctc.PVGSSVerify(auth9, G1sToPoints(num, C), G1sToPoints(num, PK1), big.NewInt(0), VrfQ, big.NewInt(0))
	receipt9, _ := bind.WaitMined(context.Background(), client, tx9)
	fmt.Println("On-chain Verification Gas cost = ", receipt9.GasUsed)

	onchainIsShareValid, _ := ctc.GetVerifyResult(&bind.CallOpts{})
	fmt.Println("On-chain Verfication result = ", onchainIsShareValid)

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
	fmt.Println("Of-chain KeyVerification result = ", ofchainIsKeyValid)

	// On-chain
	var allgasused uint64
	for i := 0; i < num; i++ {
		auth11 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(C[i]), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(new(bn128.G2).ScalarBaseMult(big.NewInt(1))))
		// tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(decShares[i].Neg(decShares[i])), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(PK2[i]))
		receipt11, _ := bind.WaitMined(context.Background(), client, tx11)
		allgasused += receipt11.GasUsed
	}
	onchainIsKeyValid, _ := ctc.GetKeyVrfResult(&bind.CallOpts{})
	// fmt.Println("order = ", bn128.Order)
	fmt.Println("On-chain KeyVerification result = ", onchainIsKeyValid)
	fmt.Println("On-chain KeyVerification result = ", allgasused)

	// fmt.Println("...........................................................Setup............................................................")

	// maabe := rwdabe.NewMAABE()

	// const num int = 100               //number of auths
	// const times int64 = 5             //test times
	// const CTsize1M = int(1024 * 1024) //the msg  iinit set 1M

	// attribs := [num][]string{}
	// auths := [num]*rwdabe.MAABEAuth{}
	// //keys := [n][]*rwdabe.MAABEKey{}
	// ksEnc := []*rwdabe.MAABEKey{}
	// ksDec := []*rwdabe.MAABEKey{}
	// Proofs := []*rwdabe.Proof{}

	// // create  authorities, each with two attributes
	// for i := 0; i < num; i++ {
	// 	authi := "auth" + strconv.Itoa(i)
	// 	attribs[i] = []string{authi + ":at1"}
	// 	// create three authorities, each with two attributes
	// 	auths[i], _ = maabe.NewMAABEAuth(authi)
	// }

	// //User Setup...(sk,pk)
	// userSk := rwdabe.RandomInt()
	// userPk := new(bn128.G1).ScalarMult(auths[0].Maabe.G1, userSk)

	// acjudges := make([]*ACJudge, 1)
	// acjudges[0] = generateACPStr(num)
	// fmt.Println("Access Control Policy:", acjudges[0].ACS)
	// //msp, _ := lib.BooleanToMSP(acjudges[0].ACS, false)
	// policyStr := ""
	// for i := 0; i < num-1; i++ {
	// 	authi := "auth" + strconv.Itoa(i)
	// 	policyStr += authi + ":at1 AND "
	// }
	// policyStr += "auth" + strconv.Itoa(num-1) + ":at1"
	// msp, _ := lib.BooleanToMSP(policyStr, false)

	// pks := []*rwdabe.MAABEPubKey{}
	// for i := 0; i < num; i++ {
	// 	pks = append(pks, auths[i].Pk)
	// }

	// fmt.Println("..........................................................Encrypy...........................................................")

	// // choose a message , the msg set 5M
	// //CTsize := CTsize1M * 1
	// //msg := strings.Repeat("a", CTsize)
	// msg := "Data sharing in the metaverse with key abuse resistance based on decentralized CP-ABE"
	// fmt.Println("The msg is:", msg)
	// // encrypt the message with the decryption policy in msp
	// ct, err := maabe.ABEEncrypt(msg, msp, pks)
	// if err != nil {
	// 	log.Println("加密发生错误:", err)
	// }

	// fmt.Println("..........................................................Request...........................................................")

	// // choose a single user's Global ID
	// gid := "gid1"
	// // authority 1 issues keys to user

	// for i := 0; i < num; i++ {
	// 	keys, _ := auths[i].ABEKeyGen(gid, attribs[i][0], userPk)
	// 	ksEnc = append(ksEnc, keys)
	// 	proofs, _ := auths[i].KeyGenPrimeAndGenProofs(keys, userPk)
	// 	Proofs = append(Proofs, proofs)
	// }

	// fmt.Println("...........................................................Verify...........................................................")

	// p1Arr := make([][]contract.DexG1Point, 0)
	// p2Arr := make([][]contract.DexG2Point, 0)
	// tmpArr := make([][]*big.Int, 0)
	// attrArr := make([]string, 0)

	// for i := 0; i < num; i++ {
	// 	intArray := rwdabe.MakeIntArry(Proofs[i])
	// 	newPoint1 := []contract.DexG1Point{G1ToPoint(ksEnc[i].Key), G1ToPoint(Proofs[i].Key), G1ToPoint(ksEnc[i].EK2), G1ToPoint(Proofs[i].EK2P)}
	// 	newPoint2 := []contract.DexG2Point{G2ToPoint(ksEnc[i].KeyPrime), G2ToPoint(Proofs[i].KeyPrime), G2ToPoint(Proofs[i].G2ToAlpha), G2ToPoint(Proofs[i].G2ToBeta)}
	// 	//offchain Checkkey
	// 	res, _ := maabe.CheckKey(userPk, ksEnc[i], Proofs[i])
	// 	if !res {
	// 		fmt.Println("offchain checkey", res)
	// 	}
	// 	p1Arr = append(p1Arr, newPoint1)
	// 	p2Arr = append(p2Arr, newPoint2)
	// 	tmpArr = append(tmpArr, intArray)
	// 	attrArr = append(attrArr, ksEnc[i].Attrib)

	// }
	// //on chain CheckKey
	// autht1 := utils.Transact(client, privatekey1, big.NewInt(0))
	// // fmt.Println(p1Arr)
	// tx3, _ := ctc.Checkkeyp(autht1, p1Arr, p2Arr, tmpArr, gid, attrArr, G1ToPoint(userPk)) //checkkey on-chain
	// receipt3, _ := bind.WaitMined(context.Background(), client, tx3)
	// fmt.Printf("Checkkeyp Gas used: %d\n", receipt3.GasUsed)

	// //on chain CheckKey
	// autht2 := utils.Transact(client, privatekey1, big.NewInt(0))
	// tx4, _ := ctc.Checkkey(autht2, p1Arr, p2Arr, tmpArr, gid, attrArr, G1ToPoint(userPk)) //checkkey on-chain
	// receipt4, _ := bind.WaitMined(context.Background(), client, tx4)
	// fmt.Printf("Checkkey Gas used: %d\n", receipt4.GasUsed)
	// Checkkeyres, _ := ctc.CheckkeyRes(&bind.CallOpts{})
	// fmt.Printf("Checkkey Checkkeyres used: %d\n", Checkkeyres)

	// //judgeAttrs
	// for _, acjudge := range acjudges {
	// 	auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
	// 	tx1, _ := ctc.Validate(auth2, acjudge.Props, acjudge.ACS)
	// 	receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
	// 	fmt.Printf("attribute number %d, Validate ACP Gas used: %d\n", num, receipt1.GasUsed)
	// }

	// fmt.Println("...........................................................Access...........................................................")

	// for i := 0; i < num; i++ {
	// 	key := auths[i].GetKey(ksEnc[i], userSk)
	// 	ksDec = append(ksDec, key)
	// }

	// // user tries to decrypt with different key combos
	// // try to decrypt all messages
	// msg1, _ := maabe.ABEDecrypt(ct, ksDec)
	// fmt.Println("Decrypt msg is:", msg1)

	// fmt.Println("Decrypt Result is:", msg1 == msg)

}
