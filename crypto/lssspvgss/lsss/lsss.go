package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
)

func multiplyMatrix(A, B [][]*big.Int) ([][]*big.Int, error) {
	if len(A) == 0 || len(A[0]) == 0 {
		return nil, fmt.Errorf("matrix A is empty")
	}
	if len(B) == 0 || len(B[0]) == 0 {
		return nil, fmt.Errorf("matrix B is empty")
	}
	n := len(A)
	m := len(A[0])
	p := len(B[0])
	if len(B) != m {
		return nil, fmt.Errorf("matrix dimension mismatch: A has %d columns, B has %d rows", m, len(B))
	}

	C := make([][]*big.Int, n)
	for i := range C {
		C[i] = make([]*big.Int, p)
		for j := range C[i] {
			C[i][j] = big.NewInt(0)
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			for k := 0; k < m; k++ {
				term := new(big.Int).Mul(A[i][k], B[k][j])
				C[i][j].Add(C[i][j], term)
				C[i][j].Mod(C[i][j], bn128.Order)
			}
		}
	}
	return C, nil
}

func Share(s *big.Int, AA *node.Node) ([]*big.Int, error) {
	matrix := Convert(AA)
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("Matrix is empty")
	}
	matrixRows := len(matrix)
	matrixCols := len(matrix[0])
	v := make([]*big.Int, matrixCols)
	v[0] = s
	for i := 0; i < matrixCols-1; i++ {
		v[i+1], _ = rand.Int(rand.Reader, bn128.Order)
		// v[i+1] = big.NewInt(int64(i + 1))
	}
	v2 := make([][]*big.Int, matrixCols)
	for i, vi := range v {
		v2[i] = []*big.Int{vi}
	}
	shares := make([]*big.Int, matrixRows)
	lambdas, _ := multiplyMatrix(matrix, v2)
	for i, lambda := range lambdas {
		shares[i] = lambda[0]
	}
	return shares, nil
}

func Recon(AA *node.Node, shares []*big.Int, I []int) (*big.Int, error) {
	matrix := Convert(AA)
	weights, err := ReconstructionWeightsForRows(matrix, I)
	if err != nil {
		return nil, err
	}
	secret := big.NewInt(0)
	for i, idx := range I {
		if idx < 0 || idx >= len(shares) {
			return nil, fmt.Errorf("share index %d out of range (shares has %d rows)", idx, len(shares))
		}
		if shares[idx] == nil {
			return nil, fmt.Errorf("share at index %d is nil", idx)
		}
		term := new(big.Int).Mul(weights[i], shares[idx])
		term.Mod(term, bn128.Order)
		secret.Add(secret, term)
		secret.Mod(secret, bn128.Order)
	}
	return secret, nil
}

func RecoverSecret(AA *node.Node, shares []*big.Int) (*big.Int, error) {
	matrix := Convert(AA)
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("Matrix is empty")
	}
	if len(shares) != len(matrix) {
		return nil, fmt.Errorf("share length mismatch: got %d, want %d", len(shares), len(matrix))
	}
	weights, err := ReconstructionWeights(matrix)
	if err != nil {
		return nil, err
	}
	secret := big.NewInt(0)
	for i := 0; i < len(shares); i++ {
		if shares[i] == nil {
			return nil, fmt.Errorf("share at index %d is nil", i)
		}
		term := new(big.Int).Mul(weights[i], shares[i])
		term.Mod(term, bn128.Order)
		secret.Add(secret, term)
		secret.Mod(secret, bn128.Order)
	}
	return secret, nil
}

func ReconstructionWeights(matrix [][]*big.Int) ([]*big.Int, error) {
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("Matrix is empty")
	}
	n := len(matrix)
	d := len(matrix[0])
	aug := make([][]*big.Int, d)
	for row := 0; row < d; row++ {
		aug[row] = make([]*big.Int, n+1)
		for col := 0; col < n; col++ {
			aug[row][col] = new(big.Int).Set(matrix[col][row])
			aug[row][col].Mod(aug[row][col], bn128.Order)
		}
		aug[row][n] = big.NewInt(0)
		if row == 0 {
			aug[row][n] = big.NewInt(1)
		}
	}

	pivotCols := make([]int, 0, d)
	pivotRows := make([]int, 0, d)
	currentRow := 0
	for col := 0; col < n && currentRow < d; col++ {
		pivotRow := -1
		for row := currentRow; row < d; row++ {
			if aug[row][col].Sign() != 0 {
				pivotRow = row
				break
			}
		}
		if pivotRow == -1 {
			continue
		}
		if pivotRow != currentRow {
			aug[currentRow], aug[pivotRow] = aug[pivotRow], aug[currentRow]
		}
		inv := new(big.Int).ModInverse(aug[currentRow][col], bn128.Order)
		if inv == nil {
			return nil, fmt.Errorf("matrix pivot is not invertible")
		}
		for k := col; k <= n; k++ {
			aug[currentRow][k].Mul(aug[currentRow][k], inv)
			aug[currentRow][k].Mod(aug[currentRow][k], bn128.Order)
		}
		for row := 0; row < d; row++ {
			if row == currentRow || aug[row][col].Sign() == 0 {
				continue
			}
			factor := new(big.Int).Set(aug[row][col])
			for k := col; k <= n; k++ {
				term := new(big.Int).Mul(factor, aug[currentRow][k])
				term.Mod(term, bn128.Order)
				aug[row][k].Sub(aug[row][k], term)
				aug[row][k].Mod(aug[row][k], bn128.Order)
			}
		}
		pivotCols = append(pivotCols, col)
		pivotRows = append(pivotRows, currentRow)
		currentRow++
	}
	for row := currentRow; row < d; row++ {
		if aug[row][n].Sign() != 0 {
			return nil, fmt.Errorf("target vector is not in the row span")
		}
	}
	weights := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		weights[i] = big.NewInt(0)
	}
	for i, col := range pivotCols {
		weights[col] = new(big.Int).Set(aug[pivotRows[i]][n])
	}
	return weights, nil
}

func SelectedRows(matrix [][]*big.Int, I []int) ([][]*big.Int, error) {
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("Matrix is empty")
	}
	rows := make([][]*big.Int, len(I))
	for i, idx := range I {
		if idx < 0 || idx >= len(matrix) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		rows[i] = make([]*big.Int, len(matrix[idx]))
		for j := range matrix[idx] {
			rows[i][j] = new(big.Int).Set(matrix[idx][j])
		}
	}
	return rows, nil
}

func ReconstructionWeightsForRows(matrix [][]*big.Int, I []int) ([]*big.Int, error) {
	rows, err := SelectedRows(matrix, I)
	if err != nil {
		return nil, err
	}
	return ReconstructionWeights(rows)
}

func GrpShare(S *bn128.G1, AA *node.Node) ([]*bn128.G1, error) {
	matrix := Convert(AA)
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("something went wrong")
	}
	matrixRows := len(matrix)
	matrixCols := len(matrix[0])
	v := make([]*big.Int, matrixCols)
	v[0] = big.NewInt(int64(1))
	for i := 0; i < matrixCols-1; i++ {
		v[i+1], _ = rand.Int(rand.Reader, bn128.Order)
		// v[i+1] = big.NewInt(int64(i + 1))
	}
	v2 := make([][]*big.Int, matrixCols)
	for i, vi := range v {
		v2[i] = []*big.Int{vi}
	}
	shares := make([]*bn128.G1, matrixRows)
	lambdas, _ := multiplyMatrix(matrix, v2)
	for i, lambda := range lambdas {
		shares[i] = new(bn128.G1).ScalarMult(S, lambda[0])
	}
	return shares, nil
}

func GrpRecon(AA *node.Node, recoverShares []*bn128.G1, I []int) (*bn128.G1, error) {
	matrix := Convert(AA)
	weights, err := ReconstructionWeightsForRows(matrix, I)
	if err != nil {
		return nil, err
	}
	return GrpReconWithWeights(recoverShares, I, weights)
}

func GrpReconWithWeights(recoverShares []*bn128.G1, I []int, weights []*big.Int) (*bn128.G1, error) {
	if len(weights) != len(I) {
		return nil, fmt.Errorf("reconstruction weight length mismatch: got %d, want %d", len(weights), len(I))
	}
	if len(recoverShares) < len(I) {
		return nil, fmt.Errorf("recover share length mismatch: got %d, want at least %d", len(recoverShares), len(I))
	}
	reconS := new(bn128.G1).ScalarBaseMult(big.NewInt(0)) // Identity point
	for i := range I {
		if i >= len(recoverShares) {
			return nil, fmt.Errorf("recover share index %d out of range (shares has %d rows)", i, len(recoverShares))
		}
		if recoverShares[i] == nil {
			return nil, fmt.Errorf("share at index %d is nil", i)
		}
		term := new(bn128.G1).ScalarMult(recoverShares[i], weights[i])
		reconS.Add(reconS, term)
	}
	return reconS, nil
}

// Extract Threshold structure
func ExtractFirstThreshold(root *node.Node) (*node.Node, []*node.Node, int, int) {
	if root == nil {
		return nil, nil, 0, 0
	}

	// If it is a leaf node, there is no threshold structure
	if root.IsLeaf {
		return nil, []*node.Node{root}, 0, 0
	}

	// The first non-leaf node is processed and its threshold structure is extracted
	t := root.T
	n := root.ChildrenNum
	children := root.Children

	// Returns the threshold structure of the current node, as well as its children
	return &node.Node{
		IsLeaf:      false,
		Children:    nil,
		ChildrenNum: n,
		T:           t,
		Idx:         root.Idx,
	}, children, t, n
}

func Convert(F_A *node.Node) [][]*big.Int {
	// Initialize L and M
	L := []*node.Node{F_A}
	M := [][]*big.Int{{big.NewInt(1)}}
	m, d := 1, 1
	z := 1 // Control loop

	for z != 0 {
		z = 0
		i := 1
		var n, t int
		var threshold *node.Node
		var remainingStructure []*node.Node

		for i <= m && z == 0 {
			currentStructure := L[i-1]
			threshold, remainingStructure, t, n = ExtractFirstThreshold(currentStructure)

			if threshold != nil {
				z = i
				break
			}
			i++
		}

		if z != 0 {
			// F_z := L[z-1]
			m2, d2 := n, t
			L2 := remainingStructure
			L1 := make([]*node.Node, len(L))
			copy(L1, L)
			M1 := make([][]*big.Int, len(M))
			for i := range M {
				M1[i] = make([]*big.Int, len(M[i]))
				copy(M1[i], M[i])
			}

			m1, d1 := m, d
			// Re-initialize L and M
			M = make([][]*big.Int, m1+m2-1)
			for i := range M {
				M[i] = make([]*big.Int, d1+d2-1)
				for j := range M[i] {
					M[i][j] = big.NewInt(0)
				}
			}
			L = make([]*node.Node, m1+m2-1)

			// Update M and L
			for u := 0; u < z-1; u++ {
				L[u] = L1[u]
				for v := 0; v < d1; v++ {
					M[u][v] = M1[u][v]
				}
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(0)
				}
			}

			for u := z - 1; u < z+m2-1; u++ {
				L[u] = L2[u-z+1]
				for v := 0; v < d1; v++ {
					M[u][v] = M1[z-1][v]
				}
				a := big.NewInt(int64((u + 1) - (z - 1)))
				x := new(big.Int).Set(a)
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = new(big.Int).Set(x)
					x.Mul(x, a)
					x.Mod(x, bn128.Order)
				}
			}

			for u := z + m2 - 1; u < m1+m2-1; u++ {
				L[u] = L1[u-m2+1]
				for v := 0; v < d1; v++ {
					M[u][v] = M1[u-m2+1][v]
				}
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(0)
				}
			}

			m, d = m1+m2-1, d1+d2-1
		}
	}

	return M
}
