package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	"pvgss/crypto/node"
	"testing"
)

func TestLSSS(t *testing.T) {

	secret, _ := rand.Int(rand.Reader, bn128.Order)

	//Access Policy 1
	nx := 5
	tx := 3
	root1 := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := node.NewNode(false, nx, tx, big.NewInt(int64(3)))
	root1.Children = []*node.Node{A, B, X}
	Xp := make([]*node.Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	//Access Policy 2
	root2 := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(1)))
	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 := node.NewNode(false, 3, 1, big.NewInt(int64(3)))
	root2.Children = []*node.Node{P_1, P_D, P_2}
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_C := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_1.Children = []*node.Node{P_A, P_B, P_C}
	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_F := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_G := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_2.Children = []*node.Node{P_E, P_F, P_G}

	//Test access policy 1
	shares1, _ := Share(secret, root1)
	lsssI1 := make([]int, tx+1)
	for i := 1; i < tx+1; i++ {
		lsssI1[i] = i + 1
	}
	reconS1, err := Recon(root1, shares1, lsssI1)
	if err != nil {
		t.Fatalf("LSSS Recon error: %v", err)
	}
	fmt.Println("LSSS original secret = ", secret)
	fmt.Println("LSSS recover secret  = ", reconS1)

	//Test access policy 2
	shares2, _ := Share(secret, root2)
	lsssI2 := []int{0, 1, 3, 4}

	// Prepare the sub-matrix for reconstruction
	reconS2, err := Recon(root2, shares2, lsssI2)
	if err != nil {
		t.Fatalf("LSSS Recon error: %v", err)
	}
	fmt.Println("LSSS original secret = ", secret)
	fmt.Println("LSSS recover secret  = ", reconS2)

}

func TestGrpLSSS(t *testing.T) {

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	S := new(bn128.G1).ScalarBaseMult(secret)

	//Access Policy 1
	nx := 5
	tx := 3
	root1 := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := node.NewNode(false, nx, tx, big.NewInt(int64(3)))
	root1.Children = []*node.Node{A, B, X}
	Xp := make([]*node.Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	//Access Policy 2
	root2 := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(1)))
	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 := node.NewNode(false, 3, 1, big.NewInt(int64(3)))
	root2.Children = []*node.Node{P_1, P_D, P_2}
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_C := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_1.Children = []*node.Node{P_A, P_B, P_C}
	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_F := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_G := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_2.Children = []*node.Node{P_E, P_F, P_G}

	//Test access policy 1
	shares1, _ := GrpShare(S, root1)
	lsssI1 := make([]int, tx+1)
	lsssI1[0] = 0
	recoverShares1 := make([]*bn128.G1, 1+tx)
	recoverShares1[0] = shares1[0]
	for i := 1; i < tx+1; i++ {
		recoverShares1[i] = shares1[i+1]
		lsssI1[i] = i + 1
	}
	reconS1, _ := GrpRecon(root1, recoverShares1, lsssI1)
	fmt.Println("original secret = ", S)
	fmt.Println("recover secret  = ", reconS1)
	if reconS1.String() == S.String() {
		fmt.Print("Secret reconstruction successful!\n")
	}

	//Test access policy 2
	shares2, _ := GrpShare(S, root2)
	lsssI2 := []int{0, 1, 3, 4}
	recoverShares2 := []*bn128.G1{shares2[0], shares2[1], shares2[3], shares2[4]}
	reconS2, _ := GrpRecon(root2, recoverShares2, lsssI2)
	fmt.Println("original secret = ", S)
	fmt.Println("recover secret  = ", reconS2)
	if reconS2.String() == S.String() {
		fmt.Print("Secret reconstruction successful!\n")
	}

}
