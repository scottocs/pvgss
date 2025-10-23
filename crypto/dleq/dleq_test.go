package dleq

import (
	"crypto/rand"
	"math/big"
	"testing"

	bn256 "pvgss/bn128"
)

func TestDLEQProveAndVerify(t *testing.T) {
	// Generate a random secret
	secret, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Create generators
	g1 := &bn256.G1{}
	g1.ScalarBaseMult(big.NewInt(1)) // g1 = generator of G1

	g2 := &bn256.G1{}
	g2.ScalarBaseMult(big.NewInt(1)) // g2 = generator of G1

	// Calculate powers
	powers := &Powers{
		G1: new(bn256.G1).ScalarMult(g1, secret), // g1^secret
		G2: new(bn256.G1).ScalarMult(g2, secret), // g1^secret
	}

	// Generate proof
	proof, err := DLEQProve(g1, g2, secret, powers)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof
	if !DLEQVerify(g1, g2, powers, proof) {
		t.Fatal("Proof verification failed")
	}
}

func TestDLEQVerifyWithWrongSecret(t *testing.T) {
	// Generate a random secret
	secret, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Generate a different secret for powers
	wrongSecret, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Fatalf("Failed to generate wrong secret: %v", err)
	}

	// Create generators
	g1 := &bn256.G1{}
	g1.ScalarBaseMult(big.NewInt(1))

	g2 := &bn256.G1{}
	g2.ScalarBaseMult(big.NewInt(1))

	// Calculate powers with wrong secret
	powers := &Powers{
		G1: new(bn256.G1).ScalarMult(g1, wrongSecret), // g1^wrongSecret
		G2: new(bn256.G1).ScalarMult(g2, wrongSecret), // g1^wrongSecret
	}

	// Generate proof with correct secret
	proof, err := DLEQProve(g1, g2, secret, powers)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof should fail
	if DLEQVerify(g1, g2, powers, proof) {
		t.Fatal("Proof verification should have failed with wrong secret")
	}
}
