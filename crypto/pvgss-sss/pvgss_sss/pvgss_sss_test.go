package pvgss_sss

import (
	// "errors"

	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-sss/gss"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPVGSS(t *testing.T) {
	nx := 1000     //the number of Watchers
	tx := nx/2 + 1 //the threshold of Watchers
	num := nx + 2  //the number of leaf nodes
	// 1. Setup
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}

	numRuns := 100 // Number of repetitions
	var totalDuration time.Duration

	// 2. Share
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
	s, _ := rand.Int(rand.Reader, bn128.Order)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _, _ = PVGSSShare(s, root, PK1)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // average time
	// averageDuration := totalDuration / time.Duration(numRuns)

	// fmt.Printf("%d Wathcers, %d threshold : average PVGSSShare time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	C, prfs, err := PVGSSShare(s, root, PK1)
	if err != nil {
		t.Fatalf("pvgss failed to share: %v\n", err)
	}

	// 3. Verify
	path1 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*gss.Node{A, B}

	I1 := make([]int, 2)
	I1[0] = 0
	I1[1] = 1

	path2 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path2.Children = []*gss.Node{A, X}

	I2 := make([]int, tx+1)
	I2[0] = 0
	for i := 0; i < tx; i++ {
		I2[i+1] = i + 2
	}

	// Verify all shares
	// the satifying path = root
	I := make([]int, nx+2)
	// I[0] = 0
	for i := 0; i < nx+2; i++ {
		I[i] = i
	}

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSVerify(C, prfs, root, PK1, root, I)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := totalDuration / time.Duration(numRuns)

	// fmt.Printf("%d Wathcers, %d threshold : average PVGSSVerify time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	isShareValid, err := PVGSSVerify(C, prfs, root, PK1, root, I)
	if err != nil || isShareValid == false {
		t.Fatalf("pvgss share verify failed: %v\n", err)
	}
	fmt.Println("isShareValid : ", isShareValid)

	// 4.PreRecon
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
		decShares[i], err = PVGSSPreRecon(C[i], SK[i])
		if err != nil {
			t.Fatalf("pvgss share decryption failed: %v\n", err)
		}
	}

	// 5.KeyVerify
	isKeyValid := make([]bool, 2)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSKeyVrf(C[0], decShares[0], PK2[0])
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := (totalDuration / time.Duration(numRuns))

	// fmt.Printf("one user : average PVGSSKeyVrf time over %d runs: %s\n", numRuns, averageDuration)

	for i := 0; i < 2; i++ { // It is a example : Verify the decryption keys of Alice and Bob
		isKeyValid[i], err = PVGSSKeyVrf(C[i], decShares[i], PK2[i])
		if err != nil || isKeyValid[i] == false {
			t.Fatalf("pvgss share decryption verify failed: %v\n", err)
		}
	}
	fmt.Println("isKeyValidRes : ", isKeyValid)

	// 6.Recon

	onrgnS := new(bn128.G1).ScalarBaseMult(s)

	// A and B
	Q1 := make([]*bn128.G1, 2)
	Q1[0] = decShares[0] //A's share
	Q1[1] = decShares[1] //B's share
	reconS1, _ := PVGSSRecon(path1, Q1)

	assert.Equal(t, onrgnS.String(), reconS1.String())
	if onrgnS.String() == reconS1.String() {
		fmt.Print("A and B reconstruct secret secessfully!\n")
	}

	// A and Watchers
	Q2 := make([]*bn128.G1, 1+tx)
	Q2[0] = decShares[0] //A's share
	// Q[1] = decShares[1] //B's share
	for i := 1; i < tx+1; i++ {
		Q2[i] = decShares[i+1]
	}
	path2 = gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path2.Children = []*gss.Node{A, X}

	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_, _ = PVGSSRecon(path2, Q2)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	averageDuration := totalDuration / time.Duration(numRuns)

	fmt.Printf("%d Wathcers, %d watchers and Alice reconstruct the secret : average PVGSSRecon time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	reconS2, _ := PVGSSRecon(path2, Q2)

	assert.Equal(t, onrgnS.String(), reconS2.String())
	if onrgnS.String() == reconS2.String() {
		fmt.Print("A and Watchers reconstruct secret secessfully!\n")
	}

	// B and Watchers
	Q3 := make([]*bn128.G1, 1+tx)
	// Q3[0] = decShares[0] //A's share
	Q3[0] = decShares[1] //B's share
	for i := 1; i < tx+1; i++ {
		Q3[i] = decShares[i+1]
	}
	path3 := gss.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path3.Children = []*gss.Node{B, X}
	reconS3, _ := PVGSSRecon(path3, Q3)

	assert.Equal(t, onrgnS.String(), reconS3.String())
	if onrgnS.String() == reconS3.String() {
		fmt.Print("B and Watchers reconstruct secret secessfully!\n")
	}
}
