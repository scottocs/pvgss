package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	// "pvgss/crypto/pvgss-lsss2/lsss"
	"pvgss/crypto/pvgss-sss/gss"
	"testing"
)

func TestExtractFirstThreshold(t *testing.T) {
	// (2 of (0, 0, 3 of (0,0, 0,0)))
	root := &gss.Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*gss.Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 4,
				T:           3,
				Idx:         big.NewInt(3),
				Children: []*gss.Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
					{IsLeaf: true, Idx: big.NewInt(4)},
				},
			},
		},
	}

	x, remainingChildren, threshold, n := ExtractFirstThreshold(root)

	fmt.Println("x = ", x)
	fmt.Println("remainingChildren", remainingChildren[0])

	fmt.Printf("The threshold structure of the stripping: (%d of %d)\n", threshold, n)
	fmt.Println("The remaining substructures:")
	for _, child := range remainingChildren {
		if child.IsLeaf {
			fmt.Printf("Leaf Node (Idx: %d)\n", child.Idx)
		} else {
			fmt.Printf("Threshold Node (T: %d, Childrennum: %d, Idx: %d)\n", child.T, child.Childrennum, child.Idx)
		}
	}

	M := Convert(root)
	fmt.Println("M[0].length = ", len(M[0]))
}

func TestMul(t *testing.T) {

	A := make([][]*big.Int, 4)
	for i := range A {
		A[i] = make([]*big.Int, 2)
	}

	B := make([][]*big.Int, 2)
	for i := range B {
		B[i] = make([]*big.Int, 1)
	}

	A[0][0] = big.NewInt(1)
	A[0][1] = big.NewInt(1)
	A[1][0] = big.NewInt(1)
	A[1][1] = big.NewInt(2)
	A[2][0] = big.NewInt(1)
	A[2][1] = big.NewInt(3)
	A[3][0] = big.NewInt(1)
	A[3][1] = big.NewInt(3)

	B[0][0] = big.NewInt(5)
	B[1][0] = big.NewInt(2)
	result, _ := MultiplyMatrix(A, B)
	PrintMatrix(result)
}

func TestGauss(t *testing.T) {
	A := make([][]*big.Int, 3)
	for i := range A {
		A[i] = make([]*big.Int, 3)
	}
	A[0][0] = big.NewInt(1)
	A[0][1] = big.NewInt(2)
	A[0][2] = big.NewInt(3)
	A[1][0] = big.NewInt(1)
	A[1][1] = big.NewInt(3)
	A[1][2] = big.NewInt(2)
	A[2][0] = big.NewInt(1)
	A[2][1] = big.NewInt(4)
	A[2][2] = big.NewInt(2)

	invA, _ := GaussJordanInverse(A)
	fmt.Println("bn128.Order = ", bn128.Order)
	fmt.Println("A's invers = ", invA)
}

func TestLSSS(t *testing.T) {
	//  (2 of (0, 0, 2 of (0, 0,0)))
	AA := &gss.Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*gss.Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 3,
				T:           2,
				Idx:         big.NewInt(3),
				Children: []*gss.Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
				},
			},
		},
	}

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	// secret := big.NewInt(int64(5))
	shares, _ := LSSSShare(secret, AA)
	// fmt.Println("shares = ", shares)

	I := make([]int, 2)
	I[0] = 0
	I[1] = 1
	// I[2] = 4
	recoverShares := make([]*big.Int, 2)
	recoverShares[0] = shares[0]
	recoverShares[1] = shares[1]
	// recoverShares[2] = shares[4]
	matrix := Convert(AA)
	reconS, _ := LSSSRecon(matrix, recoverShares, I)
	fmt.Println("original secret = ", secret)
	fmt.Println("recover secret  = ", reconS)
	if reconS.Cmp(secret) == 0 {
		fmt.Print("Secret reconstruction successful!\n")
	}
}
