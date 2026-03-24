package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/lssspvgss/opmatrix"
	"pvgss/crypto/node"
)

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
	lambdas, _ := opmatrix.MultiplyMatrix(matrix, v2)
	for i, lambda := range lambdas {
		shares[i] = lambda[0]
	}
	return shares, nil
}

func Recon(AA *node.Node, shares []*big.Int, I []int) (*big.Int, error) {
	rows := len(I)
	// Prepare the sub-matrix for reconstruction
	matrix := Convert(AA)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		if idx >= len(matrix) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		// Take the first 'rows' columns of the selected row
		if len(matrix[idx]) < rows {
			return nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
		}
		recMatrix[i] = matrix[idx][:rows]
	}
	// Compute Inverse Matrix
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)
	w, _ := opmatrix.MultiplyMatrix(one, invRecMatrix)
	shares2 := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		if shares[I[i]] == nil {
			return nil, fmt.Errorf("share at index %d is nil", i)
		}
		shares2[i] = []*big.Int{shares[I[i]]}
	}
	reconS, _ := opmatrix.MultiplyMatrix(w, shares2)
	s := reconS[0][0]
	return s, nil
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
	lambdas, _ := opmatrix.MultiplyMatrix(matrix, v2)
	for i, lambda := range lambdas {
		shares[i] = new(bn128.G1).ScalarMult(S, lambda[0])
	}
	return shares, nil
}

func GrpRecon(AA *node.Node, recoverShares []*bn128.G1, I []int) (*bn128.G1, error) {
	rows := len(I)
	// Prepare the sub-matrix for reconstruction
	matrix1 := Convert(AA)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		if idx >= len(matrix1) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix1))
		}
		// Take the first 'rows' columns of the selected row
		if len(matrix1[idx]) < rows {
			return nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix1[idx]), rows)
		}
		recMatrix[i] = matrix1[idx][:rows]
	}
	// Compute Inverse Matrix
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)
	w, _ := opmatrix.MultiplyMatrix(one, invRecMatrix)
	reconS := new(bn128.G1).ScalarBaseMult(big.NewInt(0)) // Identity point
	for i := 0; i < rows; i++ {
		if recoverShares[i] == nil {
			return nil, fmt.Errorf("share at index %d is nil", i)
		}
		term := new(bn128.G1).ScalarMult(recoverShares[i], w[0][i])
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
	n := root.Childrennum
	children := root.Children

	// Returns the threshold structure of the current node, as well as its children
	return &node.Node{
		IsLeaf:      false,
		Children:    nil,
		Childrennum: n,
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

			// Updata M and L
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
				a, x := (u+1)-(z-1), (u+1)-(z-1)
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(int64(x))
					x = (x * a) % 1000000000000000000
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
