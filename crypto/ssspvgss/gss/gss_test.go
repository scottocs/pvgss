package gss

import (
	"crypto/rand"
	"fmt"

	"math/big"

	"testing"

	bn128 "pvgss/bn128"
	// "pvgss/crypto/gss"
)

func TestGSS(t *testing.T) {
	nx := 3
	tx := 2

	root := NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := NewNode(false, nx, tx, big.NewInt(int64(3)))
	root.Children = []*Node{A, B, X}
	Xp := make([]*Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	secret, _ := rand.Int(rand.Reader, bn128.Order)

	// test GrpGSSShare
	shares, err := GSSShare(secret, root)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")

	if len(shares) != GetLen(root) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root), len(shares))
	}
	Q := shares[1:]
	path := NewNode(false, 2, 2, big.NewInt(int64(0)))

	path.Children = []*Node{B, X}

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

func TestGetLen(t *testing.T) {
	nx := 3
	tx := 2
	pks := make([]*bn128.G1, 5)
	for i := 0; i < 5; i++ {
		s, _ := rand.Int(rand.Reader, bn128.Order)
		pks[i] = new(bn128.G1).ScalarBaseMult(s)
	}

	root := NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := NewNode(false, nx, tx, big.NewInt(int64(3)))
	root.Children = []*Node{A, B, X}
	Xp := make([]*Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp
	len := GetLen(root)
	fmt.Println("len = ", len)
	// fmt.Println("rootlen = ", len(root.Children))
	rootchildlen := root.Childrennum
	fmt.Println("rootchildlen = ", rootchildlen)
}

func TestGrpGSS(t *testing.T) {
	nx := 3
	tx := 2
	pks := make([]*bn128.G1, 5)
	for i := 0; i < 5; i++ {
		s, _ := rand.Int(rand.Reader, bn128.Order)
		pks[i] = new(bn128.G1).ScalarBaseMult(s)
	}

	root := NewNode(false, 3, 2, big.NewInt(int64(0)))
	A := NewNode(true, 0, 1, big.NewInt(int64(1)))
	B := NewNode(true, 0, 1, big.NewInt(int64(2)))
	X := NewNode(false, nx, tx, big.NewInt(int64(3)))
	root.Children = []*Node{A, B, X}
	Xp := make([]*Node, nx)
	for i := 0; i < nx; i++ {
		Xp[i] = NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	X.Children = Xp

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	Secret := new(bn128.G1).ScalarBaseMult(secret)

	// test GrpGSSShare
	shares, err := GrpGSSShare(Secret, root)
	if err != nil {
		t.Errorf("GrpGSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")

	if len(shares) != GetLen(root) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root), len(shares))
	}

	// test GrpGSSRecon
	// Q := shares[:3]
	// test GrpGSSRecon
	// A and B
	Q := make([]*bn128.G1, 1+tx)
	Q[0] = shares[1]
	Q[1] = shares[2]
	Q[2] = shares[3]
	// Q := shares[:2]
	path := NewNode(false, 2, 2, big.NewInt(int64(0)))

	path.Children = []*Node{B, X}
	recoveredSecret, _, _ := GrpGSSRecon(path, Q)
	fmt.Println("orignal secret = ", Secret)
	fmt.Println("recover secret = ", recoveredSecret)

	if !(recoveredSecret.String() == Secret.String()) {
		t.Errorf("Secret reconstruction mismatch: expected %v, got %v", Secret, recoveredSecret)
	}
	// Ix := make([]*big.Int, 2)
	// for i := 0; i < 2; i++ {
	// 	Ix[i] = big.NewInt(int64(i + 1))
	// }
	// I := make([]*big.Int, 2)
	// I[0] = big.NewInt(1)
	// I[1] = big.NewInt(3)
	// WsSecret, _ := GrpRecon(shares[2:4], Ix)
	// fmt.Println("Csecret = ", WsSecret)
	// share := make([]*bn128.G1, 2)
	// share[0] = shares[0]
	// share[1] = WsSecret
	// recoveredSecret, err := GrpRecon(share, I)
	// // recoveredSecret, err := GrpRecon(shares[:2], Ix)
	// if err != nil {
	// 	t.Errorf("GrpGSSRecon failed: %v", err)
	// }
	// fmt.Println("Reconstruction successful!")

	// if !(recoveredSecret.String() == Secret.String()) {
	// 	t.Errorf("Secret reconstruction mismatch: expected %v, got %v", Secret, recoveredSecret)
	// }
}
