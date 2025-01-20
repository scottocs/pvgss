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

	// test GrpGSSRecon
	// A and B
	// Q := make([]*big.Int, 1+tx)
	// Q[0] = shares[1]
	// Q[1] = shares[2]
	// Q[2] = shares[3]
	Q := shares[1:]
	path := NewNode(false, 2, 2, big.NewInt(int64(0)))

	path.Children = []*Node{B, X}

	// A and X

	// Q = append(Q, shares[0])
	// for i := 0; i < tx; i++ {
	// 	Q = append(Q, shares[i+2])
	// }
	// I := make([]*big.Int, 1+tx+1)
	// I[0] = big.NewInt(int64(1))
	// I[1] = big.NewInt(int64(3))
	// I[2] = big.NewInt(int64(1))
	// I[3] = big.NewInt(int64(2))
	// I = append(I, big.NewInt(int64(1)))
	// I = append(I, big.NewInt(int64(3)))
	// for i := 0; i < tx; i++ {
	// 	I = append(I, big.NewInt(int64(i+1)))
	// }
	recoveredSecret, _, _ := GSSRecon(path, Q)
	fmt.Println("orignal secret = ", secret)
	fmt.Println("recover secret = ", recoveredSecret)
	// Verify that the recovered secret is the same as the original secret
	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Secret reconstruction mismatch: expected %v, got %v", secret, recoveredSecret)
	}
}
