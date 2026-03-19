package gssreconwithvrf

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/ssspvgss/sss"
	"testing"
)

func TestGSSReconWithVrf(t *testing.T) {

	// ==========================================
	// Part 1: Test SSS Scheme (Baseline)
	// ==========================================
	n := 5         // The number of shares
	threshold := 3 // threshold
	// Generate a random secret
	s, _ := rand.Int(rand.Reader, bn128.Order)
	sssShares, err := sss.Share(s, n, threshold)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	// //RScode Check
	// verRScode := RSCodeVerify(sssShares, threshold)
	// fmt.Printf("RScode=%v\n", verRScode)
	//Reconstruct Polynomial Check
	// verReconPoly, _ := ReconPolynomial(sssShares, threshold)
	// fmt.Printf("ReconPoly=%v\n", verReconPoly)
	sharesVals := append([]*big.Int{}, sssShares[:threshold]...)
	reconCoeffi, _ := reconCoefficient(sharesVals)
	fmt.Printf("Reconstruct coefficients: %v\n", reconCoeffi)

	sssI := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		sssI[i] = big.NewInt(int64(i + 1))
	}
	secret, err := sss.Recon(sssShares, sssI, threshold)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)
	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}

	// ==========================================
	// Part 2: Test LSSS Scheme
	// ==========================================
	// Construct the Access Tree
	// root := lsss.NewNode(false, 3, 3, big.NewInt(int64(0)))
	// P_1 := lsss.NewNode(false, 3, 2, big.NewInt(int64(1)))
	// P_D := lsss.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// P_2 := lsss.NewNode(false, 3, 1, big.NewInt(int64(3)))
	// root.Children = []*lsss.Node{P_1, P_D, P_2}
	// P_A := lsss.NewNode(true, 0, 1, big.NewInt(int64(1)))
	// P_B := lsss.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// P_C := lsss.NewNode(true, 0, 1, big.NewInt(int64(3)))
	// P_1.Children = []*lsss.Node{P_A, P_B, P_C}
	// P_E := lsss.NewNode(true, 0, 1, big.NewInt(int64(1)))
	// P_F := lsss.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// P_G := lsss.NewNode(true, 0, 1, big.NewInt(int64(3)))
	// P_2.Children = []*lsss.Node{P_E, P_F, P_G}
	// // Transfer Access Policy to LSSS Matrix
	// matrix := lsss.Convert(root)
	// lsssShares, _ := lsss.Share(secret, matrix)
	// //Calculate the parity-check matrix
	// verMatrix := GenerateParityMatrix(matrix)
	// opmatrix.PrintMatrix(verMatrix)
	// //Transfer secret shares as shares matrix with 1 column
	// sharesMatrix := opmatrix.SetToMatrix(lsssShares)
	// //sharesMatrix[0][0] = big.NewInt(int64(8))
	// resultMatrix, _ := opmatrix.MultiplyMatrix(verMatrix, sharesMatrix)
	// if opmatrix.IsZeroMatrixMod(resultMatrix) {
	// 	fmt.Printf("Valid LSSS Shares\n")
	// } else {
	// 	fmt.Printf("Invalid LSSS Shares\n")
	// }
	// lsssI := []int{0, 1, 3, 4}
	// rows := len(lsssI)
	// // Prepare the sub-matrix for reconstruction
	// recMatrix := make([][]*big.Int, rows)
	// for i := 0; i < rows; i++ {
	// 	idx := lsssI[i]
	// 	if idx >= len(matrix) {
	// 		t.Fatalf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
	// 	}
	// 	// Take the first 'rows' columns of the selected row
	// 	if len(matrix[idx]) < rows {
	// 		t.Fatalf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
	// 	}
	// 	recMatrix[i] = matrix[idx][:rows]
	// }
	// // Compute Inverse Matrix
	// invRecMatrix, err := lsss.GaussJordanInverse(recMatrix)
	// if err != nil {
	// 	t.Fatalf("Matrix inversion failed: %v", err)
	// }
	// reconS, err := lsss.Recon(invRecMatrix, lsssShares, lsssI)
	// if err != nil {
	// 	t.Fatalf("LSSS Recon error: %v", err)
	// }
	// fmt.Println("LSSS original secret = ", secret)
	// fmt.Println("LSSS recover secret  = ", reconS)

}
