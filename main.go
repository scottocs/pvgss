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

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvgss/bn128"

	"pvgss/crypto/pvgss-lsss2/lsss"

	pvgss_lsss "pvgss/crypto/pvgss-lsss2/pvgss_lsss"
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

func IntToBig(array []int) []*big.Int {
	bigArray := make([]*big.Int, len(array))
	for i := 0; i < len(array); i++ {
		bigArray[i] = big.NewInt(int64(array[i]))
	}
	return bigArray
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

	// ====================================== Preset content ======================================
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

	// Key Pairs
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)

	// //========================================= PVGSS-LSSS Test =========================================
	fmt.Print("============================= PVGSS-LSSS Test =============================\n")

	// 1. PVGSSSetup
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = pvgss_lsss.PVGSSSetup()
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
	I00 := make([]int, 1+tx)
	I00[0] = 0
	for i := 0; i < tx; i++ {
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

	// On-chain
	// Upload lprfs
	auth21 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx21, _ := ctc.LUploadProof(auth21, G1sToPoints(num, lprfs.Cp), lprfs.Xc, lprfs.Shat, lprfs.Shatarry)
	_, _ = bind.WaitMined(context.Background(), client, tx21)

	// On-chain PVGSSVerify
	// Input : Secret share(lC), public key(PK1), LSSS matrix, user for verification (I0), where 0 denotes Alic, 1 denotes Bob, and 2 ∼ nx + 2 denotes Watchers

	auth22 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx22, _ := ctc.LSSSPVGSSVerify(auth22, G1sToPoints(num, lC), G1sToPoints(num, PK1), invRecMatrix0, invRecMatrix, IntToBig(I0), IntToBig(I00))
	receipt22, _ := bind.WaitMined(context.Background(), client, tx22)
	fmt.Println("On-chain Shares verification Gas cost = ", receipt22.GasUsed)

	// Get On-chain PVGSSVerify result
	lonchainIsShareValid, _ := ctc.GetLSSSVerifyResult(&bind.CallOpts{})
	fmt.Println("On-chain Shares verfication result = ", lonchainIsShareValid)

	// 4. PVGSSPreRecon
	ldecShares := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		ldecShares[i], _ = pvgss_lsss.PVGSSPreRecon(lC[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	lofchainIsKeyValid := make([]bool, 2)
	for i := 0; i < 2; i++ {
		lofchainIsKeyValid[i], _ = pvgss_lsss.PVGSSKeyVrf(lC[i], ldecShares[i], PK2[i])
	}
	fmt.Println("Off-chain DecShares verification result =  = ", lofchainIsKeyValid)

	// On-chain
	// This function is called to check the correctness of the decrypted shares (i.e., the decryption keys) provided by Alice and Bob before recovering the secret
	var lAllGasUsed uint64
	for i := 0; i < 2; i++ {
		auth23 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx23, _ := ctc.PVGSSKeyVrf(auth23, G1ToPoint(lC[i]), G1ToPoint(ldecShares[i]), G2ToPoint(PK2[i]), G2ToPoint(new(bn128.G2).ScalarBaseMult(big.NewInt(1))))
		// tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(decShares[i].Neg(decShares[i])), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(PK2[i]))
		receipt25, _ := bind.WaitMined(context.Background(), client, tx23)
		lAllGasUsed += receipt25.GasUsed
	}
	lonchainIsKeyValid, _ := ctc.GetKeyVrfResult(&bind.CallOpts{})
	// fmt.Println("order = ", bn128.Order)
	fmt.Println("On-chain DecShares verification result =  = ", lonchainIsKeyValid)
	fmt.Println("On-chain DecSHares verification Gas cost = ", lAllGasUsed)

	//========================================= PVGSS-SSS Test ==========================================
	fmt.Print("============================= PVGSS-SSS Test =============================\n")
	// 1. PVGSSSetup
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = pvgss_sss.PVGSSSetup()
	}

	// 2. PVGSSShare
	C, prfs, _ := pvgss_sss.PVGSSShare(secret, root, PK1)

	// Of-chain: construct paths that satisfy the access control structure
	// Case1: A and B
	path1 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*gss.Node{A, B}
	I1 := make([]int, 2)
	I1[0] = 0
	I1[1] = 1

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
	isShareValid, _ := pvgss_sss.PVGSSVerify(C, prfs, root, PK1, path1, I1)

	fmt.Println("Off-chain Shares verfication result = ", isShareValid)

	// On-chain
	// Upload prfs
	auth8 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx8, _ := ctc.UploadProof(auth8, G1sToPoints(num, prfs.Cp), prfs.Xc, prfs.Shat, prfs.Shatarry)
	_, _ = bind.WaitMined(context.Background(), client, tx8)

	// Input : Secret share(C), public key(PK1), user for verification (VrfQ), where 0 denotes Alic, 1 denotes Bob, and 2 ∼ nx + 2 denotes Watchers, the start idx (0)
	auth9 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx9, _ := ctc.PVGSSVerify(auth9, G1sToPoints(num, C), G1sToPoints(num, PK1), VrfQ)
	receipt9, _ := bind.WaitMined(context.Background(), client, tx9)
	fmt.Println("On-chain Shares verification Gas cost = ", receipt9.GasUsed)

	onchainIsShareValid, _ := ctc.GetVerifyResult(&bind.CallOpts{})
	fmt.Println("On-chain Shares verfication result = ", onchainIsShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		decShares[i], _ = pvgss_sss.PVGSSPreRecon(C[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	ofchainIsKeyValid := make([]bool, 2)
	for i := 0; i < 2; i++ {
		ofchainIsKeyValid[i], _ = pvgss_sss.PVGSSKeyVrf(C[i], decShares[i], PK2[i])
	}
	fmt.Println("Off-chain DecShares verification result =  = ", ofchainIsKeyValid)

	// On-chain
	// This function is called to check the correctness of the decrypted shares (i.e., the decryption keys) provided by Alice and Bob before recovering the secret
	var allgasused uint64
	for i := 0; i < 2; i++ {
		auth11 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(C[i]), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(new(bn128.G2).ScalarBaseMult(big.NewInt(1))))
		// tx11, _ := ctc.PVGSSKeyVrf(auth11, G1ToPoint(decShares[i].Neg(decShares[i])), G1ToPoint(decShares[i]), G2ToPoint(PK2[i]), G2ToPoint(PK2[i]))
		receipt11, _ := bind.WaitMined(context.Background(), client, tx11)
		allgasused += receipt11.GasUsed
	}
	onchainIsKeyValid, _ := ctc.GetKeyVrfResult(&bind.CallOpts{})
	// fmt.Println("order = ", bn128.Order)
	fmt.Println("On-chain DecShares verification result =  = ", onchainIsKeyValid)
	fmt.Println("On-chain DecSHares verification Gas cost = ", allgasused)

}
