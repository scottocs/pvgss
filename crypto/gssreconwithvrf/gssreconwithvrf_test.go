package gssreconwithvrf

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/lssspvgss/lsss"
	"pvgss/crypto/lssspvgss/opmatrix"
	"pvgss/crypto/node"
	"pvgss/crypto/ssspvgss/gss"
	"testing"
	"time"
)

func TestGSSReconWithVrf(t *testing.T) {
	n := int64(500)

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	//	Construct the Access Tree
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
	matrix := lsss.Convert(root)

	// ==========================================
	// Part 1: Test GSS Scheme
	// ==========================================
	//Calculate gss shares
	gssshares, err := gss.GSSShare(secret, root)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")
	if len(gssshares) != gss.GetLen(root) {
		t.Errorf("Shares length mismatch: expected %d, got %d", gss.GetLen(root), len(gssshares))
	}
	//gssshares[0] = big.NewInt(1)

	//Verify the validation of gss shares
	//Method 1:
	// Restore the polynomial layer by layer from bottom to top
	// Each polynomial is used to verify last n-t child nodes.
	var verGSSRP bool
	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		verGSSRP, _ = ReconPolynomial(root, gssshares)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("ReconPolynomial Time Used is %v us\n", (endtime-starttime)/n)
	if verGSSRP {
		fmt.Printf("GSS Shares Pass ReconPolynomial Test!!!\n")
		var Q []*big.Int
		Q = append(Q, gssshares[0])
		Q = append(Q, gssshares[1])
		Q = append(Q, gssshares[3])
		Q = append(Q, gssshares[4])
		path := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
		P_1 := node.NewNode(false, 2, 2, big.NewInt(int64(1)))
		P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_2 := node.NewNode(false, 1, 1, big.NewInt(int64(3)))
		path.Children = []*node.Node{P_1, P_D, P_2}
		P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_1.Children = []*node.Node{P_A, P_B}
		P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_2.Children = []*node.Node{P_E}
		recoveredSecret, _, err := gss.GSSRecon(path, Q)
		if err != nil {
			t.Fatalf("Reconstruction failed: %v", err)
		}
		fmt.Println("orignal secret = ", secret)
		fmt.Println("recover secret = ", recoveredSecret)
	} else {
		fmt.Printf("GSS Shares No Pass ReconPolynomial Test!!!\n")
	}

	//Method 2:
	// Excute RSCode Verification by layer from bottom to top

	var verGSSRS bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		verGSSRS, _ = RecurRSCode(root, gssshares)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("RecurRSCode Time Used is %v us\n", (endtime-starttime)/n)
	if verGSSRS {
		fmt.Printf("GSS Shares Pass RSCode Test!!!\n")
		var Q []*big.Int
		Q = append(Q, gssshares[0])
		Q = append(Q, gssshares[1])
		Q = append(Q, gssshares[3])
		Q = append(Q, gssshares[4])
		path := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
		P_1 := node.NewNode(false, 2, 2, big.NewInt(int64(1)))
		P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_2 := node.NewNode(false, 1, 1, big.NewInt(int64(3)))
		path.Children = []*node.Node{P_1, P_D, P_2}
		P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_1.Children = []*node.Node{P_A, P_B}
		P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_2.Children = []*node.Node{P_E}
		recoveredSecret, _, err := gss.GSSRecon(path, Q)
		if err != nil {
			t.Fatalf("Reconstruction failed: %v", err)
		}
		fmt.Println("orignal secret = ", secret)
		fmt.Println("recover secret = ", recoveredSecret)
	} else {
		fmt.Printf("GSS Shares No Pass RSCode Test!!!\n")
	}
	// //Method 3.1: Generate a global sparse parity check matrix H through recursively process each non-leaf node
	// //Calculate the sparse matrix
	// verSPMatrix, _ := GenerateSparseMatrix(root)
	// fmt.Printf("The Sparse Matrix of Shamir Shares:\n")
	// opmatrix.PrintMatrix(verSPMatrix)
	// //Transfer secret shares as shares matrix with 1 column
	// gsssharesMatrix := opmatrix.SetToMatrix(gssshares)
	// //gsssharesMatrix[0][0] = big.NewInt(int64(8))
	// resultSPMatrix, _ := opmatrix.MultiplyMatrix(verSPMatrix, gsssharesMatrix)
	// if opmatrix.IsZeroMatrixMod(resultSPMatrix) {
	// 	fmt.Printf("GSS Shares Pass Sparse Matrix Test\n")
	// 	var Q []*big.Int
	// 	Q = append(Q, gssshares[0])
	// 	Q = append(Q, gssshares[1])
	// 	Q = append(Q, gssshares[3])
	// 	Q = append(Q, gssshares[4])
	// 	path := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
	// 	P_1 := node.NewNode(false, 2, 2, big.NewInt(int64(1)))
	// 	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// 	P_2 := node.NewNode(false, 1, 1, big.NewInt(int64(3)))
	// 	path.Children = []*node.Node{P_1, P_D, P_2}
	// 	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	// 	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
	// 	P_1.Children = []*node.Node{P_A, P_B}
	// 	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
	// 	P_2.Children = []*node.Node{P_E}
	// 	recoveredSecret, _, err := gss.GSSRecon(path, Q)
	// 	if err != nil {
	// 		t.Fatalf("Reconstruction failed: %v", err)
	// 	}
	// 	fmt.Println("orignal secret = ", secret)
	// 	fmt.Println("recover secret = ", recoveredSecret)
	// } else {
	// 	fmt.Printf("GSS Shares No Pass Sparse Matrix Test\n")
	// }

	// ==========================================
	// Part 2: Test LSSS Scheme
	// ==========================================
	fmt.Printf("Start to LSSS Scheme!!!\n")
	//Calculate lsss shares
	lsssshares, _ := lsss.Share(secret, root)
	//Method 1:
	// Restore the polynomial layer by layer from bottom to top
	// Each polynomial is used to verify last n-t child nodes.

	var verLSSSRP bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		verLSSSRP, _ = ReconPolynomial(root, lsssshares)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("ReconPolynomial Time Used is %v us\n", (endtime-starttime)/n)
	if verLSSSRP {
		fmt.Printf("LSSS Shares Pass ReconPolynomial Test!!!\n")
		I := []int{0, 1, 3, 4}
		var Q []*big.Int
		Q = append(Q, gssshares[0])
		Q = append(Q, gssshares[1])
		Q = append(Q, gssshares[3])
		Q = append(Q, gssshares[4])
		path := node.NewNode(false, 3, 3, big.NewInt(int64(0)))
		P_1 := node.NewNode(false, 2, 2, big.NewInt(int64(1)))
		P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_2 := node.NewNode(false, 1, 1, big.NewInt(int64(3)))
		path.Children = []*node.Node{P_1, P_D, P_2}
		P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)))
		P_1.Children = []*node.Node{P_A, P_B}
		P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)))
		P_2.Children = []*node.Node{P_E}
		recoveredSecret, _ := lsss.Recon(root, lsssshares, I)
		if err != nil {
			t.Fatalf("Reconstruction failed: %v", err)
		}
		fmt.Println("orignal secret = ", secret)
		fmt.Println("recover secret = ", recoveredSecret)
	} else {
		fmt.Printf("LSSS Shares No Pass ReconPolynomial Test!!!\n")
	}
	//Method 2:
	// Excute RSCode Verification by layer from bottom to top

	var verLSSSRS bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		verLSSSRS, _ = ReconPolynomial(root, lsssshares)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("RecurRSCode Time Used is %v us\n", (endtime-starttime)/n)
	if verLSSSRS {
		fmt.Printf("LSSS Shares Pass RSCode Test!!!\n")
		lsssI := []int{0, 1, 3, 4}
		recoveredSecret, err := lsss.Recon(root, lsssshares, lsssI)
		if err != nil {
			t.Fatalf("Reconstruction failed: %v", err)
		}
		fmt.Println("orignal secret = ", secret)
		fmt.Println("recover secret = ", recoveredSecret)
	} else {
		fmt.Printf("LSSS Shares No Pass RSCode Test!!!\n")
	}

	//Methed 3.2:Verify through parity-check matrix

	//Transfer secret shares as shares matrix with 1 column
	lssssharesMatrix := opmatrix.SetToMatrix(lsssshares)

	//Calculate the parity-check matrix
	var verLSSSPC bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		verPCMatrix := GenerateParityMatrix(matrix)
		resultPCMatrix, _ := opmatrix.MultiplyMatrix(verPCMatrix, lssssharesMatrix)
		verLSSSPC = opmatrix.IsZeroMatrixMod(resultPCMatrix)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Parity-Check Time Used is %v us\n", (endtime-starttime)/n)

	//sharesMatrix[0][0] = big.NewInt(int64(8))

	if verLSSSPC {
		fmt.Printf("LSSS Shares Pass Parity-Check Matrix Test\n")
		lsssI := []int{0, 1, 3, 4}
		//recoverLSSSShares := []*big.Int{lsssshares[0], lsssshares[1], lsssshares[3], lsssshares[4]}
		reconS, err := lsss.Recon(root, lsssshares, lsssI)
		if err != nil {
			t.Fatalf("LSSS Recon error: %v", err)
		}
		fmt.Println("LSSS original secret = ", secret)
		fmt.Println("LSSS recover secret  = ", reconS)
	} else {
		fmt.Printf("LSSS Shares No Pass Parity-Check Matrix Test\n")
	}
}
