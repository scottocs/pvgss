package pvgss_sss

import (
	// "errors"

	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-sss/gss"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPVGSS(t *testing.T) {
	nx := 10       //the number of Watchers
	tx := nx/2 + 1 //the threshold of Watchers
	nr := 3        //树根访问控制结构
	tr := nr - 1
	num := nx + 2 //叶子节点数量
	// 1. Setup
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}

	// 2. Share
	// 创建访问控制结构
	root := gss.NewNode(false, nr, tr, big.NewInt(int64(0)))
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
	C, prfs, err := PVGSSShare(s, root, PK1)
	if err != nil {
		t.Fatalf("pvgss failed to share: %v\n", err)
	}

	// 3. Verify
	path1 := gss.NewNode(false, tr, tr, big.NewInt(int64(0)))
	path1.Children = []*gss.Node{A, B}

	isShareValid, err := PVGSSVerify(C, prfs, root, PK1, path1)
	if err != nil || isShareValid == false {
		t.Fatalf("pvgss share verify failed: %v\n", err)
	}
	fmt.Println("isShareValid : ", isShareValid)

	// 4.PreRecon
	decShares := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		decShares[i], err = PVGSSPreRecon(C[i], SK[i])
		if err != nil {
			t.Fatalf("pvgss share decryption failed: %v\n", err)
		}
	}

	// 5.KeyVerify
	isKeyValid := make([]bool, num)
	for i := 0; i < num; i++ {
		isKeyValid[i], err = PVGSSKeyVrf(C[i], decShares[i], PK2[i])
		if err != nil || isKeyValid[i] == false {
			t.Fatalf("pvgss share decryption verify failed: %v\n", err)
		}
	}
	fmt.Println("isKeyValidRes : ", isKeyValid)

	// 6.Recon

	onrgnS := new(bn128.G1).ScalarBaseMult(s)

	// A and B
	Q1 := make([]*bn128.G1, tr)
	Q1[0] = decShares[0] //A's share
	Q1[1] = decShares[1] //B's share
	reconS1, _ := PVGSSRecon(path1, Q1, C)

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
	path2 := gss.NewNode(false, tr, tr, big.NewInt(int64(0)))
	path2.Children = []*gss.Node{A, X}
	reconS2, _ := PVGSSRecon(path2, Q2, C)

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
	path3 := gss.NewNode(false, tr, tr, big.NewInt(int64(0)))
	path3.Children = []*gss.Node{B, X}
	reconS3, _ := PVGSSRecon(path3, Q3, C)

	assert.Equal(t, onrgnS.String(), reconS3.String())
	if onrgnS.String() == reconS3.String() {
		fmt.Print("B and Watchers reconstruct secret secessfully!\n")
	}
}
