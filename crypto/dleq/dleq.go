package dleq

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	bn256 "pvgss/bn128"
)

// DLEQProof represents a discrete logarithm equivalence proof
type DLEQProof struct {
	C1        *bn256.G1 // Commitment 1: g1 * r
	C2        *bn256.G1 // Commitment 2: g1 * r
	Challenge *big.Int  // Challenge value: hash(powers.G1, powers.G2, c1, c2)
	Response  *big.Int  // Response value: r + challenge * secret
}

// Powers represents the power tuple (g1^secret, g1^secret)
type Powers struct {
	G1 *bn256.G1
	G2 *bn256.G1
}

// generateChallenge generates a challenge value using hash(power1, power2, c1, c2)
func generateChallenge(power1 *bn256.G1, power2 *bn256.G1, c1 *bn256.G1, c2 *bn256.G1) *big.Int {
	var combinedBytes []byte

	// Append power1 (G1 element)
	combinedBytes = append(combinedBytes, power1.Marshal()...)

	// Append power2 (G1 element)
	combinedBytes = append(combinedBytes, power2.Marshal()...)

	// Append c1 (G1 element)
	combinedBytes = append(combinedBytes, c1.Marshal()...)

	// Append c2 (G1 element)
	combinedBytes = append(combinedBytes, c2.Marshal()...)

	// Hash the combined bytes
	hash := sha256.Sum256(combinedBytes)

	// Convert hash to big.Int and reduce modulo Order
	hashBigInt := new(big.Int).SetBytes(hash[:])
	hashBigInt.Mod(hashBigInt, bn256.Order)

	return hashBigInt
}

// DLEQProve generates a DLEQ proof
// g1: generator of G1 group
// g2: generator of G1 group
// secret: secret value
// powers: power tuple (g1^secret, g1^secret)
func DLEQProve(g1 *bn256.G1, g2 *bn256.G1, secret *big.Int, powers *Powers) (*DLEQProof, error) {
	// Generate random number r
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, err
	}

	// Calculate commitments
	// c1 = g1 * r
	c1 := new(bn256.G1).ScalarMult(g1, r)

	// c2 = g1*r
	c2 := new(bn256.G1).ScalarMult(g2, r)

	// Generate challenge value using hash(powers.G1, powers.G2, c1, c2)
	challenge := generateChallenge(powers.G1, powers.G2, c1, c2)

	// Calculate response: response = r + challenge * secret
	response := new(big.Int)
	response.Mul(challenge, secret)
	response.Add(response, r)
	response.Mod(response, bn256.Order)

	return &DLEQProof{
		C1:        c1,
		C2:        c2,
		Challenge: challenge,
		Response:  response,
	}, nil
}

// DLEQVerify verifies a DLEQ proof
// g1: generator of G1 group
// g2: generator of G1 group
// powers: power tuple (g1^secret, g1^secret)
// proof: proof to verify
func DLEQVerify(g1 *bn256.G1, g2 *bn256.G1, powers *Powers, proof *DLEQProof) bool {
	// Generate the challenge value using hash(powers.G1, powers.G2, c1, c2)
	challenge := generateChallenge(powers.G1, powers.G2, proof.C1, proof.C2)

	// Verify: g1^response == c1 + powers.G1^challenge
	// i.e.: g1^response == c1 * powers.G1^challenge

	// Calculate g1^response
	g1Response := new(bn256.G1).ScalarMult(g1, proof.Response)

	// Calculate powers.G1^challenge
	powersG1Challenge := new(bn256.G1).ScalarMult(powers.G1, challenge)

	// Calculate c1 + powers.G1^challenge
	leftSide := new(bn256.G1).Add(proof.C1, powersG1Challenge)

	// Verify first equation
	if !bytes.Equal(g1Response.Marshal(), leftSide.Marshal()) {
		return false
	}

	// Verify: g1*response == c2 * powers.G2^challenge
	// i.e.: g1*response == c2 * powers.G2^challenge

	// Calculate g1*response
	g1Response2 := new(bn256.G1).ScalarMult(g2, proof.Response)

	// Calculate powers.G2^challenge
	powersG2Challenge := new(bn256.G1).ScalarMult(powers.G2, challenge)

	// Calculate c2 * powers.G2^challenge
	rightSide := new(bn256.G1).Add(proof.C2, powersG2Challenge)

	// Verify second equation
	return bytes.Equal(g1Response2.Marshal(), rightSide.Marshal())
}
