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
	// nx := 3
	// tx := 2

	// root := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
	// A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	// B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// X := node.NewNode(false, nx, tx, big.NewInt(int64(3)))
	// root.Children = []*node.Node{A, B, X}
	// Xp := make([]*node.Node, nx)
	// for i := 0; i < nx; i++ {
	// 	Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	// }
	// X.Children = Xp
	root := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(1)))
	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 := node.NewNode(false, 3, 1, big.NewInt(int64(3)))
	root.Children = []*node.Node{P_1, P_D, P_2}
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_C := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_1.Children = []*node.Node{P_A, P_B, P_C}
	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_F := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_G := node.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_2.Children = []*node.Node{P_E, P_F, P_G}

	// test GSSShare
	secret, _ := rand.Int(rand.Reader, bn128.Order)
	shares, err := GSSShare(secret, root)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")
	if len(shares) != GetLen(root) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root), len(shares))
	}

	// Q := shares[1:]
	// path := node.NewNode(false, 2, 2, big.NewInt(int64(0)))
	// path.Children = []*node.Node{B, X}
	var Q []*big.Int
	Q = append(Q, shares[0])
	Q = append(Q, shares[1])
	Q = append(Q, shares[3])
	Q = append(Q, shares[4])
	path := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(1)))
	P_D = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 = node.NewNode(false, 1, 1, big.NewInt(int64(3)))
	path.Children = []*node.Node{P_1, P_D, P_2}
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_1.Children = []*node.Node{P_A, P_B}
	P_E = node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_2.Children = []*node.Node{P_E}
	recoveredSecret, _, err := GSSRecon(path, Q)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	fmt.Println("orignal secret = ", secret)
	fmt.Println("recover secret = ", recoveredSecret)
	// Verify that the recovered secret is the same as the original secret
	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Secret reconstruction mismatch: expected %v, got %v", secret, recoveredSecret)
	}

}

// func TestGrpGSS(t *testing.T) {
// 	nx := 3
// 	tx := 2
// 	pks := make([]*bn128.G1, 5)
// 	for i := 0; i < 5; i++ {
// 		s, _ := rand.Int(rand.Reader, bn128.Order)
// 		pks[i] = new(bn128.G1).ScalarBaseMult(s)
// 	}

// 	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)))
// 	A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
// 	B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
// 	X := node.NewNode(false, nx, tx, big.NewInt(int64(3)))
// 	root.Children = []*node.Node{A, B, X}
// 	Xp := make([]*node.Node, nx)
// 	for i := 0; i < nx; i++ {
// 		Xp[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
// 	}
// 	X.Children = Xp

// 	secret, _ := rand.Int(rand.Reader, bn128.Order)
// 	Secret := new(bn128.G1).ScalarBaseMult(secret)

// 	// test GrpGSSShare
// 	shares, err := GrpGSSShare(Secret, root)
// 	if err != nil {
// 		t.Errorf("GrpGSSShare failed: %v", err)
// 	}
// 	fmt.Println("Shares generated successfully!")

// 	if len(shares) != GetLen(root) {
// 		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root), len(shares))
// 	}

// 	// test GrpGSSRecon
// 	// Q := shares[:3]
// 	// test GrpGSSRecon
// 	// A and B
// 	Q := make([]*bn128.G1, 1+tx)
// 	Q[0] = shares[1]
// 	Q[1] = shares[2]
// 	Q[2] = shares[3]
// 	// Q := shares[:2]
// 	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)))

// 	path.Children = []*node.Node{B, X}
// 	recoveredSecret, _, _ := GrpGSSRecon(path, Q)
// 	fmt.Println("orignal secret = ", Secret)
// 	fmt.Println("recover secret = ", recoveredSecret)

// 	if !(recoveredSecret.String() == Secret.String()) {
// 		t.Errorf("Secret reconstruction mismatch: expected %v, got %v", Secret, recoveredSecret)
// 	}
// 	// Ix := make([]*big.Int, 2)
// 	// for i := 0; i < 2; i++ {
// 	// 	Ix[i] = big.NewInt(int64(i + 1))
// 	// }
// 	// I := make([]*big.Int, 2)
// 	// I[0] = big.NewInt(1)
// 	// I[1] = big.NewInt(3)
// 	// WsSecret, _ := GrpRecon(shares[2:4], Ix)
// 	// fmt.Println("Csecret = ", WsSecret)
// 	// share := make([]*bn128.G1, 2)
// 	// share[0] = shares[0]
// 	// share[1] = WsSecret
// 	// recoveredSecret, err := GrpRecon(share, I)
// 	// // recoveredSecret, err := GrpRecon(shares[:2], Ix)
// 	// if err != nil {
// 	// 	t.Errorf("GrpGSSRecon failed: %v", err)
// 	// }
// 	// fmt.Println("Reconstruction successful!")

// 	// if !(recoveredSecret.String() == Secret.String()) {
// 	// 	t.Errorf("Secret reconstruction mismatch: expected %v, got %v", Secret, recoveredSecret)
// 	// }
// }
