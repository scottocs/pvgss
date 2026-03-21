package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	"pvgss/crypto/gssreconwithvrf"
	"pvgss/crypto/lssspvgss/opmatrix"
	"testing"
)

func TestExtractFirstThreshold(t *testing.T) {
	// (2 of (0, 0, 3 of (0,0, 0,0)))
	root := &Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 4,
				T:           3,
				Idx:         big.NewInt(3),
				Children: []*Node{
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
	result, _ := opmatrix.MultiplyMatrix(A, B)
	opmatrix.PrintMatrix(result)
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

	invA, _ := opmatrix.GaussJordanInverse(A)
	fmt.Println("bn128.Order = ", bn128.Order)
	fmt.Println("A's invers = ", invA)
}

func TestLSSS(t *testing.T) {
	//  (2 of (0, 0, 2 of (0, 0,0)))
	AA := &Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 3,
				T:           2,
				Idx:         big.NewInt(3),
				Children: []*Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
				},
			},
		},
	}

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	// secret := big.NewInt(int64(5))
	matrix := Convert(AA)
	shares, _ := Share(secret, matrix)

	//Calculate the parity-check matrix
	verMatrix := gssreconwithvrf.GenerateParityMatrix(matrix)
	fmt.Printf("Order=%v\n", bn128.Order)
	opmatrix.PrintMatrix(verMatrix)

	//Transfer secret shares as shares matrix with 1 column
	sharesMatrix := opmatrix.SetToMatrix(shares)
	//sharesMatrix[0][0] = big.NewInt(int64(8))
	resultMatrix, _ := opmatrix.MultiplyMatrix(verMatrix, sharesMatrix)
	if opmatrix.IsZeroMatrixMod(resultMatrix) {
		fmt.Printf("Valid LSSS Shares\n")
		I := make([]int, 2)
		I[0] = 0
		I[1] = 1
		// I[2] = 4
		recoverShares := make([]*big.Int, 2)
		recoverShares[0] = shares[0]
		recoverShares[1] = shares[1]
		// recoverShares[2] = shares[4]
		rows := len(I)
		// matrix := Convert(AA)
		recMatrix := make([][]*big.Int, rows)
		for i := 0; i < rows; i++ {
			recMatrix[i] = matrix[I[i]][:rows]
		}
		invRecMatrix, _ := opmatrix.GaussJordanInverse(recMatrix)
		reconS, _ := Recon(invRecMatrix, recoverShares, I)
		fmt.Println("original secret = ", secret)
		fmt.Println("recover secret  = ", reconS)
		if reconS.Cmp(secret) == 0 {
			fmt.Print("Secret reconstruction successful!\n")
		}
	} else {
		fmt.Printf("Invalid LSSS Shares\n")
	}

}

func TestGrpLSSS(t *testing.T) {
	// MSP =  (2 of (A, B, (2 of (P1, P2, P3))))
	AA := &Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 3,
				T:           2,
				Idx:         big.NewInt(3),
				Children: []*Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
				},
			},
		},
	}
	secret, _ := rand.Int(rand.Reader, bn128.Order)
	S := new(bn128.G1).ScalarBaseMult(secret)
	shares, _ := GrpShare(S, AA)

	I := make([]int, 3)
	I[0] = 0
	I[1] = 2
	I[2] = 4
	recoverShares := make([]*bn128.G1, 3)
	recoverShares[0] = shares[0]
	recoverShares[1] = shares[2]
	recoverShares[2] = shares[4]
	rows := len(I)
	matrix := Convert(AA)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ := opmatrix.GaussJordanInverse(recMatrix)
	reconS, _ := GrpRecon(invRecMatrix, recoverShares, I)
	fmt.Println("original secret = ", S)
	fmt.Println("recover secret  = ", reconS)
	if reconS.String() == S.String() {
		fmt.Print("Secret reconstruction successful!\n")
	}
}
