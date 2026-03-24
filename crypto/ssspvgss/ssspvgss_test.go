package ssspvgss

import (
	// "errors"

	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/dleq"
	"pvgss/crypto/node"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSSPVGSS(t *testing.T) {

	//Acceess policy
	nx := 10       //the number of Watchers
	tx := nx/2 + 1 //the threshold of Watchers
	num := nx + 2  //the number of leaf nodes
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

	//Authorized Set
	//1) Alice and Bob
	path1 := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*node.Node{A, B}
	I1 := []int{0, 1}
	//2) Alice and Watchers
	path2 := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	reconX := node.NewNode(false, tx, tx, big.NewInt(int64(3)))
	path2.Children = []*node.Node{A, reconX}
	reconXp := make([]*node.Node, tx)
	for i := 0; i < tx; i++ {
		reconXp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	reconX.Children = reconXp
	//3) Bob and Watchers
	path3 := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path3.Children = []*node.Node{B, reconX}

	// 1. Setup
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}

	// 2. Share

	//2.2 Generates PVGSS shares
	s, _ := rand.Int(rand.Reader, bn128.Order)
	C, prfs, err := PVGSSShare(s, root, PK1)
	if err != nil {
		t.Fatalf("pvgss failed to share: %v\n", err)
	}

	//3. Verify all PVGSS shares via gssreconwithvrf
	isShareValid, err := PVGSSVerify(C, prfs, root, PK1, path1, I1)
	if err != nil || isShareValid == false {
		t.Fatalf("pvgss share verify failed: %v\n", err)
	}
	fmt.Println("isShareValid : ", isShareValid)

	// 4.PreRecon
	decShares := make([]*bn128.G1, num)
	proofs := make([]*dleq.DLEQProof, num)
	for i := 0; i < num; i++ {
		decShares[i], proofs[i], err = PVGSSPreRecon(C[i], SK[i])
		if err != nil {
			t.Fatalf("pvgss share decryption failed: %v\n", err)
		}
	}

	// 5.KeyVerify
	isKeyValid := make([]bool, num)
	for i := 0; i < num; i++ { // It is a example : Verify the decryption keys of Alice and Bob
		isKeyValid[i], err = PVGSSKeyVrf(C[i], decShares[i], PK1[i], proofs[i])
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
	Q2[0] = decShares[0] //Alice's share
	for i := 1; i < tx+1; i++ {
		Q2[i] = decShares[i+1]
	}
	reconS2, _ := PVGSSRecon(path2, Q2)
	fmt.Printf("reconS2=%v\n", reconS2)
	assert.Equal(t, onrgnS.String(), reconS2.String())
	if onrgnS.String() == reconS2.String() {
		fmt.Print("Alice and Watchers reconstruct secret secessfully!\n")
	}

	// B and Watchers
	Q3 := make([]*bn128.G1, 1+tx)
	Q3[0] = decShares[1] //Bob's share
	for i := 1; i < tx+1; i++ {
		Q3[i] = decShares[i+1]
	}
	reconS3, _ := PVGSSRecon(path3, Q3)
	fmt.Printf("reconS3=%v\n", reconS3)
	assert.Equal(t, onrgnS.String(), reconS3.String())
	if onrgnS.String() == reconS3.String() {
		fmt.Print("Bob and Watchers reconstruct secret secessfully!\n")
	}
}
