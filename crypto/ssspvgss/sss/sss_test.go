package sss

import (
	"crypto/rand"
	"fmt"

	"math/big"
	bn128 "pvgss/bn128"
	"testing"
)

func TestSSS(t *testing.T) {
	n := 5         // The number of shares
	threshold := 3 // threshold

	// Generate a random secret
	s, _ := rand.Int(rand.Reader, bn128.Order)

	shares, err := Share(s, n, threshold)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	I := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = big.NewInt(int64(i + 1))
	}

	secret, err := Recon(shares, I, threshold)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)

	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}
}

func TestGrpSSS(t *testing.T) {
	// 1.Set the original secret value
	s, _ := rand.Int(rand.Reader, bn128.Order)
	S := new(bn128.G1).ScalarBaseMult(s)
	fmt.Println("orignal secret = ", S)

	// 2.Set threshold structure
	n := 5
	threshold := 3

	// 3.Call GrpShare to generate secret shares
	shares, err := GrpShare(S, n, threshold)
	if err != nil {
		t.Fatalf("Error in GrpShare: %v", err)
	}

	// 4.
	I := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = big.NewInt(int64(i + 1))
	}

	Secret, err := GrpRecon(shares[:threshold], I)
	if err != nil {
		t.Fatalf("Error in GrpRecon: %v", err)
	}
	fmt.Println("recover secret = ", Secret)

	// 7. Verify that the reconstructed secret is the same as the original secret
	if S.String() != Secret.String() {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
