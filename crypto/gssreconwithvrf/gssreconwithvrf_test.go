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
)

func TestGSSReconWithVrf(t *testing.T) {

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
	verGSSRP, _ := ReconPolynomial(root, gssshares)
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
	verResultRS, _ := ReconPolynomial(root, gssshares)
	if verResultRS {
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
	//Method 3.1: Generate a global sparse parity check matrix H through recursively process each non-leaf node
	//Calculate the sparse matrix
	verSPMatrix, _ := GenerateSparseMatrix(root)
	opmatrix.PrintMatrix(verSPMatrix)
	//Transfer secret shares as shares matrix with 1 column
	gsssharesMatrix := opmatrix.SetToMatrix(gssshares)
	//gsssharesMatrix[0][0] = big.NewInt(int64(8))
	resultSPMatrix, _ := opmatrix.MultiplyMatrix(verSPMatrix, gsssharesMatrix)
	if opmatrix.IsZeroMatrixMod(resultSPMatrix) {
		fmt.Printf("GSS Shares Pass Sparse Matrix Test\n")
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
		fmt.Printf("GSS Shares No Pass Sparse Matrix Test\n")
	}

	//Test
	// 初始化根节点: (n=3, t=2) -> 需要3个子分支中的2个
	testRoot := node.NewNode(false, 3, 2, big.NewInt(int64(0)))

	// --- 分支 1: 4个叶子 (n=4, t=3) ---
	branch1 := node.NewNode(false, 4, 3, big.NewInt(int64(1)))
	leavesB1 := make([]*node.Node, 4)
	for i := 0; i < 4; i++ {
		// 叶子节点 ID: 1, 2, 3, 4
		leavesB1[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	branch1.Children = leavesB1

	// --- 分支 2: 5个叶子 (n=5, t=2) ---
	branch2 := node.NewNode(false, 5, 2, big.NewInt(int64(2)))
	leavesB2 := make([]*node.Node, 5)
	for i := 0; i < 5; i++ {
		// 叶子节点 ID: 5, 6, 7, 8, 9
		leavesB2[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+5)))
	}
	branch2.Children = leavesB2

	// --- 分支 3: 复合结构 (共6个叶子) ---
	// 父节点 (n=2, t=2) -> 必须同时满足子节点A 和 子节点B
	branch3Parent := node.NewNode(false, 2, 2, big.NewInt(int64(3)))

	// 子节点 A: (n=3, t=2), 3个叶子
	subBranch3A := node.NewNode(false, 3, 2, big.NewInt(int64(4)))
	leavesB3A := make([]*node.Node, 3)
	for i := 0; i < 3; i++ {
		// 叶子节点 ID: 10, 11, 12
		leavesB3A[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+10)))
	}
	subBranch3A.Children = leavesB3A

	// 子节点 B: (n=3, t=3), 3个叶子
	subBranch3B := node.NewNode(false, 3, 3, big.NewInt(int64(5)))
	leavesB3B := make([]*node.Node, 3)
	for i := 0; i < 3; i++ {
		// 叶子节点 ID: 13, 14, 15
		leavesB3B[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+13)))
	}
	subBranch3B.Children = leavesB3B

	// 组装分支3
	branch3Parent.Children = []*node.Node{subBranch3A, subBranch3B}

	// --- 组装根节点 ---
	testRoot.Children = []*node.Node{branch1, branch2, branch3Parent}
	verSPMatrix, _ = GenerateSparseMatrix(root)
	opmatrix.PrintMatrix(verSPMatrix)
	//Transfer secret shares as shares matrix with 1 column
	gsssharesMatrix = opmatrix.SetToMatrix(gssshares)
	//gsssharesMatrix[0][0] = big.NewInt(int64(8))
	resultSPMatrix, _ = opmatrix.MultiplyMatrix(verSPMatrix, gsssharesMatrix)
	if opmatrix.IsZeroMatrixMod(resultSPMatrix) {
		fmt.Printf("GSS Shares Pass Sparse Matrix Test\n")
	}

	// ==========================================
	// Part 2: Test LSSS Scheme
	// ==========================================
	fmt.Printf("Start to LSSS Scheme!!!\n")
	//Calculate lsss shares
	lsssshares, _ := lsss.Share(secret, root)
	//Method 1:
	verLSSSRP, _ := ReconPolynomial(root, lsssshares)
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
		recoveredSecret, _ := lsss.Recon(root, Q, I)
		if err != nil {
			t.Fatalf("Reconstruction failed: %v", err)
		}
		fmt.Println("orignal secret = ", secret)
		fmt.Println("recover secret = ", recoveredSecret)
	} else {
		fmt.Printf("LSSS Shares No Pass ReconPolynomial Test!!!\n")
	}

	//Methed 3.2:Verify through parity-check matrix
	//Calculate the parity-check matrix
	verPCMatrix := GenerateParityMatrix(matrix)
	opmatrix.PrintMatrix(verPCMatrix)

	//Transfer secret shares as shares matrix with 1 column
	lssssharesMatrix := opmatrix.SetToMatrix(lsssshares)
	//sharesMatrix[0][0] = big.NewInt(int64(8))
	resultPCMatrix, _ := opmatrix.MultiplyMatrix(verPCMatrix, lssssharesMatrix)
	if opmatrix.IsZeroMatrixMod(resultPCMatrix) {
		fmt.Printf("LSSS Shares Pass Parity-Check Matrix Test\n")
		lsssI := []int{0, 1, 3, 4}
		recoverLSSSShares := []*big.Int{lsssshares[0], lsssshares[1], lsssshares[3], lsssshares[4]}
		reconS, err := lsss.Recon(root, recoverLSSSShares, lsssI)
		if err != nil {
			t.Fatalf("LSSS Recon error: %v", err)
		}
		fmt.Println("LSSS original secret = ", secret)
		fmt.Println("LSSS recover secret  = ", reconS)
	} else {
		fmt.Printf("LSSS Shares No Pass Parity-Check Matrix Test\n")
	}
}
