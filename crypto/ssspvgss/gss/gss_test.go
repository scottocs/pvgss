package gss

import (
	"crypto/rand"
	"fmt"

	"math/big"

	"testing"

	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
	// "pvgss/crypto/gss"
)

func TestGSS(t *testing.T) {
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

	//Test Access Policy 1
	shares1, err := GSSShare(secret, root1)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully under access policy 1!")
	if len(shares1) != GetLen(root1) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root1), len(shares1))
	}
	Q1 := shares1[1:]
	path1 := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*node.Node{B, X}
	recoveredSecret1, _, err := GSSRecon(path1, Q1)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	fmt.Println("orignal secret = ", secret)
	fmt.Println("recover secret = ", recoveredSecret1)
	// Verify that the recovered secret is the same as the original secret
	if recoveredSecret1.Cmp(secret) != 0 {
		t.Errorf("Secret reconstruction mismatch under access policy 1: expected %v, got %v", secret, recoveredSecret1)
	}

	//Test Access Policy 2
	shares2, err := GSSShare(secret, root2)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully under access policy 2!")
	if len(shares2) != GetLen(root2) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root2), len(shares2))
	}
	var Q2 []*big.Int
	Q2 = append(Q2, shares2[0])
	Q2 = append(Q2, shares2[1])
	Q2 = append(Q2, shares2[3])
	Q2 = append(Q2, shares2[4])
	path2 := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(1)))
	P_D = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 = node.NewNode(false, 1, 1, big.NewInt(int64(3)))
	path2.Children = []*node.Node{P_1, P_D, P_2}
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_1.Children = []*node.Node{P_A, P_B}
	P_E = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_2.Children = []*node.Node{P_E}
	recoveredSecret2, _, err := GSSRecon(path2, Q2)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	fmt.Println("orignal secret = ", secret)
	fmt.Println("recover secret = ", recoveredSecret2)
	// Verify that the recovered secret is the same as the original secret
	if recoveredSecret2.Cmp(secret) != 0 {
		t.Errorf("Secret reconstruction mismatch under access policy 2: expected %v, got %v", secret, recoveredSecret2)
	}

}

func TestGrpGSS(t *testing.T) {

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	Secret := new(bn128.G1).ScalarBaseMult(secret)

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

	// Test access policy 1
	shares1, err := GrpGSSShare(Secret, root1)
	if err != nil {
		t.Errorf("GrpGSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")

	if len(shares1) != GetLen(root1) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root1), len(shares1))
	}
	Q1 := shares1[1:]
	path1 := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	path1.Children = []*node.Node{B, X}
	recoveredSecret1, _, _ := GrpGSSRecon(path1, Q1)
	fmt.Println("orignal secret = ", Secret)
	fmt.Println("recover secret = ", recoveredSecret1)
	if !(recoveredSecret1.String() == Secret.String()) {
		t.Errorf("Secret reconstruction mismatch under access policy 1: expected %v, got %v", Secret, recoveredSecret1)
	}

	// Test access policy 1
	shares2, err := GrpGSSShare(Secret, root2)
	if err != nil {
		t.Errorf("GrpGSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")

	if len(shares2) != GetLen(root1) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root2), len(shares2))
	}
	var Q2 []*bn128.G1
	Q2 = append(Q2, shares2[0])
	Q2 = append(Q2, shares2[1])
	Q2 = append(Q2, shares2[3])
	Q2 = append(Q2, shares2[4])
	path2 := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(1)))
	P_D = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 = node.NewNode(false, 1, 1, big.NewInt(int64(3)))
	path2.Children = []*node.Node{P_1, P_D, P_2}
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_1.Children = []*node.Node{P_A, P_B}
	P_E = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_2.Children = []*node.Node{P_E}
	recoveredSecret2, _, _ := GrpGSSRecon(path2, Q2)
	fmt.Println("orignal secret = ", Secret)
	fmt.Println("recover secret = ", recoveredSecret2)
	if !(recoveredSecret2.String() == Secret.String()) {
		t.Errorf("Secret reconstruction mismatch: expected under access policy 2 %v, got %v", Secret, recoveredSecret2)
	}
}
