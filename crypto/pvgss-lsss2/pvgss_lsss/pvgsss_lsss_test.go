package pvgss_lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	// "pvgss/crypto/pvgsslsss/lsss"
	"testing"
	"time"

	"pvgss/crypto/pvgss-lsss2/lsss"
	"pvgss/crypto/pvgss-sss/gss"

	"github.com/stretchr/testify/assert"
)

func TestPVGSS(t *testing.T) {
	// 构造测试树 (2 of (0, 0, 2 of (0, 0,0)))
	// 1. PVGSSSetup
	num := 5
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}
	AA := &gss.Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*gss.Node{
			{IsLeaf: true, Idx: big.NewInt(1)}, // 叶子节点
			{IsLeaf: true, Idx: big.NewInt(2)}, // 叶子节点
			{
				IsLeaf:      false,
				Childrennum: 3,
				T:           2,
				Idx:         big.NewInt(3),
				Children: []*gss.Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
				},
			},
		},
	}
	// secret
	s, _ := rand.Int(rand.Reader, bn128.Order)
	// 2. PVGSSShare
	C, prfs, err := PVGSSShare(s, AA, PK1)
	if err != nil {
		t.Fatalf("pvgss failed to share: %v\n", err)
	}

	I0 := make([]int, 2)
	I0[0] = 0
	I0[1] = 1
	martix := lsss.Convert(AA)
	// 3. PVGSSVerify
	isShareValid, err := PVGSSVerify(C, prfs, martix, PK1, I0)
	if err != nil || isShareValid == false {
		t.Fatalf("pvgss share verify failed: %v\n", err)
	}
	fmt.Println("isShareValid : ", isShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		decShares[i], err = PVGSSPreRecon(C[i], SK[i])
		if err != nil {
			t.Fatalf("pvgss share decryption failed: %v\n", err)
		}
	}

	// 5. PVGSSKeyVrf
	isKeyValid := make([]bool, num)
	for i := 0; i < num; i++ {
		isKeyValid[i], err = PVGSSKeyVrf(C[i], decShares[i], PK2[i])
		if err != nil || isKeyValid[i] == false {
			t.Fatalf("pvgss share decryption verify failed: %v\n", err)
		}
	}
	fmt.Println("isKeyValidRes : ", isKeyValid)

	onrgnS := new(bn128.G1).ScalarBaseMult(s)

	// 6. PVGSSRecon
	// matrix := lsss.Convert(AA)
	// A and B
	I1 := I0
	Q1 := make([]*bn128.G1, 2)
	Q1[0] = decShares[0]
	Q1[1] = decShares[1]
	reconS1, _ := PVGSSRecon(AA, Q1, I1)

	assert.Equal(t, onrgnS.String(), reconS1.String())
	if onrgnS.String() == reconS1.String() {
		fmt.Print("A and B reconstruct secret secessfully!\n")
	}

	// A and Watchers
	I2 := make([]int, 3)
	I2[0] = 0
	I2[1] = 2
	I2[2] = 3
	Q2 := make([]*bn128.G1, 3)
	Q2[0] = decShares[0]
	Q2[1] = decShares[2]
	Q2[2] = decShares[3]
	reconS2, _ := PVGSSRecon(AA, Q2, I2)
	assert.Equal(t, onrgnS.String(), reconS2.String())
	if onrgnS.String() == reconS2.String() {
		fmt.Print("A and Watchers reconstruct secret secessfully!\n")
	}

	// B and Watchers
	I3 := make([]int, 3)
	I3[0] = 1
	I3[1] = 2
	I3[2] = 3
	Q3 := make([]*bn128.G1, 3)
	Q3[0] = decShares[1]
	Q3[1] = decShares[2]
	Q3[2] = decShares[3]

	reconS3, _ := PVGSSRecon(AA, Q3, I3)
	assert.Equal(t, onrgnS.String(), reconS3.String())
	if onrgnS.String() == reconS3.String() {
		fmt.Print("B and Watchers reconstruct secret secessfully!\n")
	}
}

// Performance test
func TestLSSSPVGSS(t *testing.T) {
	nx := 1000     // the number of Watchers
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
	onrgnS := new(bn128.G1).ScalarBaseMult(secret)

	// Key Pairs
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)

	numRuns := 1 // Number of repetitions
	var totalDuration time.Duration

	// 1. PVGSSSetup
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}

	// 2. PVGSSShare
	// test PVGSShare

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _, _ = PVGSSShare(secret, root, PK1)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // average time
	// averageDuration := totalDuration / time.Duration(numRuns)

	// fmt.Printf("%d Wathcers, %d threshold : average PVGSSShare time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	C, prfs, _ := PVGSSShare(secret, root, PK1)

	// 3. PVGSSVerify
	I0 := make([]int, 2)
	I0[0] = 0
	I0[1] = 1
	matrix := lsss.Convert(root)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSVerify(C, prfs, matrix, PK1, I0)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := totalDuration / time.Duration(numRuns)

	// fmt.Printf("%d Wathcers, %d threshold : average PVGSSVerify time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	// Off-chain
	isShareValid, _ := PVGSSVerify(C, prfs, matrix, PK1, I0)

	fmt.Println("Off-chain Shares verfication result = ", isShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn128.G1, num)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSPreRecon(C[0], SK[0])
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := (totalDuration / time.Duration(numRuns))

	// fmt.Printf("one user : average PVGSSPreRecon time over %d runs: %s\n", numRuns, averageDuration)

	for i := 0; i < num; i++ {
		decShares[i], _ = PVGSSPreRecon(C[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	ofchainIsKeyValid := make([]bool, 2)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSKeyVrf(C[0], decShares[0], PK2[0])
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := (totalDuration / time.Duration(numRuns))

	// fmt.Printf("one user : average PVGSSKeyVrf time over %d runs: %s\n", numRuns, averageDuration)

	for i := 0; i < 2; i++ { // It is a example : Verify the decryption keys of Alice and Bob
		ofchainIsKeyValid[i], _ = PVGSSKeyVrf(C[i], decShares[i], PK2[i])
	}
	fmt.Println("Off-chain DecShares verification result = ", ofchainIsKeyValid)

	// 6. PVGSSRecon

	// A and Watchers
	I := make([]int, 1+tx)
	I[0] = 0
	for i := 0; i < tx; i++ {
		I[i+1] = i + 2
	}
	Q := make([]*bn128.G1, 1+tx)
	for i := 0; i < len(I); i++ {
		Q[i] = decShares[I[i]]
	}

	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_, _ = PVGSSRecon(root, Q, I)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	averageDuration := totalDuration / time.Duration(numRuns)

	fmt.Printf("%d Wathcers, %d watchers and Alice reconstruct the secret : average PVGSSRecon time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	reconS, _ := PVGSSRecon(root, Q, I)
	if onrgnS.String() == reconS.String() {
		fmt.Print("A and Watchers reconstruct secret secessfully!\n")
	}
}
