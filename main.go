package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	contract "pvgss/compile/contract/Dex"

	// "pvgss/crypto/rwdabe"
	"pvgss/utils"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvgss/bn128"

	"pvgss/crypto/dleq"
	"pvgss/crypto/lssspvgss/lsss"

	lssspvgss "pvgss/crypto/lssspvgss"
	"pvgss/crypto/node"
	"pvgss/crypto/ssspvgss"
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

func IntToBig(array []int) []*big.Int {
	bigArray := make([]*big.Int, len(array))
	for i := 0; i < len(array); i++ {
		bigArray[i] = big.NewInt(int64(array[i]))
	}
	return bigArray
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

	ctc, _ := contract.NewDex(common.HexToAddress(address.Hex()), client)

	// ====================================== Preset content ======================================
	nx := 10       // the number of Watchers
	tx := nx/2 + 1 // the threshold of Watchers
	num := nx + 2  // the number of leaf nodes

	// Off-chain: construct the access control structure
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := node.NewNode(false, nx, tx, big.NewInt(int64(3)))
	root.Children = []*node.Node{A, B, X}
	Xp := make([]*node.Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	// Generate secret values randomly
	secret, _ := rand.Int(rand.Reader, bn128.Order)

	// Key Pairs
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)

	// //========================================= PVGSS-LSSS Test =========================================
	fmt.Print("============================= PVGSS-LSSS Test =============================\n")

	// 1. PVGSSSetup
	for i := 0; i < num; i++ {
		SK[i], PK1[i] = lssspvgss.PVGSSSetup()
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
	I00 := make([]int, 1+tx)
	I00[0] = 0
	for i := 0; i < tx; i++ {
		I00[i+1] = i + 2
	}
	weights, _ := lsss.ReconstructionWeightsForRows(matrix, I00)
	lisShareValid, _ := lssspvgss.PVGSSVerify(lC, lprfs, root, PK1)

	fmt.Println("Off-chain Shares verification result = ", lisShareValid)

	// On-chain PVGSSVerify
	// Input : Secret share(lC), public key(PK1), LSSS matrix, user for verification (I0), where 0 denotes Alic, 1 denotes Bob, and 2 ∼ nx + 2 denotes Watchers

	auth22 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx22, _ := ctc.LSSSPVGSSVerify(auth22, G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry, G1sToPoints(num, lC), G1sToPoints(num, PK1), weights0, weights, IntToBig(I0), IntToBig(I00))
	receipt22, _ := bind.WaitMined(context.Background(), client, tx22)
	fmt.Println("On-chain Shares verification Gas cost = ", receipt22.GasUsed)

	// 4. PVGSSPreRecon
	ldecShares := make([]*bn128.G1, num)
	lproofs := make([]*dleq.DLEQProof, num)
	for i := 0; i < num; i++ {
		ldecShares[i], lproofs[i], _ = lssspvgss.PVGSSPreRecon(lC[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	loffchainIsKeyValid := make([]bool, 2)
	for i := 0; i < 2; i++ {
		loffchainIsKeyValid[i], _ = lssspvgss.PVGSSKeyVrf(lC[i], ldecShares[i], PK1[i], lproofs[i])
	}
	fmt.Println("Off-chain DecShares verification result =  = ", loffchainIsKeyValid)

	// On-chain
	// This function is called to check the correctness of the decrypted shares (i.e., the decryption keys) provided by Alice and Bob before recovering the secret
	var lAllGasUsed uint64
	for i := 0; i < 2; i++ {
		auth23 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx23, _ := ctc.PVGSSKeyVrf(auth23, G1ToPoint(lC[i]), G1ToPoint(ldecShares[i]), G1ToPoint(PK1[i]), G1ToPoint(lproofs[i].C1), G1ToPoint(lproofs[i].C2), lproofs[i].Challenge, lproofs[i].Response)
		receipt25, _ := bind.WaitMined(context.Background(), client, tx23)
		lAllGasUsed += receipt25.GasUsed
	}
	fmt.Println("On-chain DecShares verification Gas cost = ", lAllGasUsed)

	//========================================= PVGSS-SSS Test ==========================================
	fmt.Print("============================= PVGSS-SSS Test =============================\n")
	// 1. PVGSSSetup
	for i := 0; i < num; i++ {
		SK[i], PK1[i] = ssspvgss.PVGSSSetup()
	}

	// 2. PVGSSShare
	C, prfs, _ := ssspvgss.PVGSSShare(secret, root, PK1)

	// A and B and Watchers
	auth1_4 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx1_4, _ := ctc.CreatePath(auth1_4, big.NewInt(int64(nx)), big.NewInt(int64(tx)), big.NewInt(4))
	_, _ = bind.WaitMined(context.Background(), client, tx1_4)

	VrfQ := make([]*big.Int, 2+tx)
	// VrfQ[0] = big.NewInt(1)
	for i := 0; i < tx+2; i++ {
		VrfQ[i] = big.NewInt(int64(i))
	}

	// 3. PVGSSVerify
	// Off-chain
	isShareValid, _ := ssspvgss.PVGSSVerify(C, prfs, root, PK1)

	fmt.Println("Off-chain Shares verification result = ", isShareValid)

	// Input : Secret share(C), public key(PK1), user for verification (VrfQ), where 0 denotes Alic, 1 denotes Bob, and 2 ∼ nx + 2 denotes Watchers, the start idx (0)
	auth9 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx9, _ := ctc.PVGSSVerify(auth9, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry, G1sToPoints(num, C), G1sToPoints(num, PK1), VrfQ)
	receipt9, _ := bind.WaitMined(context.Background(), client, tx9)
	fmt.Println("On-chain Shares verification Gas cost = ", receipt9.GasUsed)

	// 4. PVGSSPreRecon
	decShares := make([]*bn128.G1, num)
	proofs := make([]*dleq.DLEQProof, num)
	for i := 0; i < num; i++ {
		decShares[i], proofs[i], _ = ssspvgss.PVGSSPreRecon(C[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	offchainIsKeyValid := make([]bool, 2)
	for i := 0; i < 2; i++ {
		offchainIsKeyValid[i], _ = ssspvgss.PVGSSKeyVrf(C[i], decShares[i], PK1[i], proofs[i])
	}
	fmt.Println("Off-chain DecShares verification result =  = ", offchainIsKeyValid)

	// On-chain
	// This function is called to check the correctness of the decrypted shares (i.e., the decryption keys) provided by Alice and Bob before recovering the secret
	var allGasUsed uint64
	for i := 0; i < 2; i++ {
		auth11 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(C[i]), G1ToPoint(decShares[i]), G1ToPoint(PK1[i]), G1ToPoint(proofs[i].C1), G1ToPoint(proofs[i].C2), proofs[i].Challenge, proofs[i].Response)
		receipt11, _ := bind.WaitMined(context.Background(), client, tx11)
		allGasUsed += receipt11.GasUsed
	}
	fmt.Println("On-chain DecShares verification Gas cost = ", allGasUsed)

}
