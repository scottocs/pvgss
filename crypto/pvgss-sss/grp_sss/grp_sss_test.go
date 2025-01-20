package grp_sss

import (
	"crypto/rand"
	"fmt"

	"math/big"
	bn128 "pvgss/bn128"
	"testing"
	// "time"
)

func TestGss(t *testing.T) {
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

	// 5.Calculate the Lagrange coefficients
	// lambdas, err := PrecomputeLagrangeCoefficients(I)
	// if err != nil {
	// 	t.Fatalf("Error in PrecomputeLagrangeCoefficients: %v", err)
	// }

	// 6.Call GrpRecon to reconstruct
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
