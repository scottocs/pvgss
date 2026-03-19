package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/lssspvgss/opmatrix"
)

type Node struct {
	IsLeaf      bool
	Children    []*Node
	Childrennum int
	T           int
	Idx         *big.Int
}

func Share(s *big.Int, matrix [][]*big.Int) ([]*big.Int, error) {
	// matrix := Convert(AA)
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
	// PrintMatrix(lambdas)
	for i, lambda := range lambdas {
		shares[i] = lambda[0]
	}
	return shares, nil
}

func Recon(invRecMatrix [][]*big.Int, shares []*big.Int, I []int) (*big.Int, error) {
	// matrix := Convert(AA)
	rows := len(I)
	// recMatrix := make([][]*big.Int, rows)
	// for i := 0; i < len(I); i++ {
	// 	recMatrix[i] = matrix[I[i]][:rows]
	// }
	// invRecMatrix, _ := GaussJordanInverse(recMatrix)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)
	w, _ := opmatrix.MultiplyMatrix(one, invRecMatrix)
	shares2 := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		shares2[i] = []*big.Int{shares[I[i]]}
	}
	reconS, _ := opmatrix.MultiplyMatrix(w, shares2)
	s := reconS[0][0]
	return s, nil
}

// Extract Threshold structure
func ExtractFirstThreshold(root *Node) (*Node, []*Node, int, int) {
	if root == nil {
		return nil, nil, 0, 0
	}

	// If it is a leaf node, there is no threshold structure
	if root.IsLeaf {
		return nil, []*Node{root}, 0, 0
	}

	// The first non-leaf node is processed and its threshold structure is extracted
	t := root.T
	n := root.Childrennum
	children := root.Children

	// Returns the threshold structure of the current node, as well as its children
	return &Node{
		IsLeaf:      false,
		Children:    nil,
		Childrennum: n,
		T:           t,
		Idx:         root.Idx,
	}, children, t, n
}

func NewNode(IsLeaf bool, num int, T int, idx *big.Int) *Node {
	return &Node{
		IsLeaf:      IsLeaf,
		Children:    []*Node{},
		Childrennum: num,
		T:           T,
		Idx:         idx,
	}
}

func Convert(F_A *Node) [][]*big.Int {
	// Initialize L and M
	L := []*Node{F_A}
	M := [][]*big.Int{{big.NewInt(1)}}
	m, d := 1, 1
	z := 1 // Control loop

	for z != 0 {
		z = 0
		i := 1
		var n, t int
		var threshold *Node
		var remainingStructure []*Node

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
			L1 := make([]*Node, len(L))
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
			L = make([]*Node, m1+m2-1)

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

// GaussJordanInverse computes the inverse of matrix A using Gauss-Jordan elimination.
// It returns the inverse matrix if it exists, otherwise returns an error.
// @TODO to optimize in the future
func GaussJordanInverse(A [][]*big.Int) ([][]*big.Int, error) {
	p := bn128.Order
	// Check if the matrix is square
	n := len(A)
	for i := 0; i < n; i++ {
		if len(A[i]) != n {
			return nil, fmt.Errorf("matrix must be square")
		}
	}

	// Create augmented matrix [A | I]
	augmented := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		augmented[i] = make([]*big.Int, 2*n)
		for j := 0; j < n; j++ {
			augmented[i][j] = new(big.Int).Set(A[i][j]) // Copy A into the augmented matrix
			augmented[i][n+j] = big.NewInt(0)           // Initialize the right side with 0
		}
		augmented[i][n+i] = big.NewInt(1) // Set the right side to the identity matrix
	}
	// fmt.Print("for1 end\n")

	// Perform Gauss-Jordan elimination
	for i := 0; i < n; i++ {
		// Make the diagonal element 1
		if augmented[i][i].Sign() == 0 {
			// Find a row below row i where the element in column i is non-zero
			found := false
			for j := i + 1; j < n; j++ {
				if augmented[j][i].Sign() != 0 {
					// Swap row i with row j
					augmented[i], augmented[j] = augmented[j], augmented[i]
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("matrix is singular and cannot be inverted")
			}
		}

		// Inverse of the pivot element
		inv := new(big.Int).ModInverse(augmented[i][i], p)
		for j := 0; j < 2*n; j++ {
			augmented[i][j].Mul(augmented[i][j], inv)
			augmented[i][j].Mod(augmented[i][j], p)
		}

		// Eliminate the rest of the column
		for j := 0; j < n; j++ {
			if j != i {
				// Subtract multiples of row i from row j to make the off-diagonal elements 0
				factor := new(big.Int).Set(augmented[j][i])
				for k := 0; k < 2*n; k++ {
					augmented[j][k].Sub(augmented[j][k], new(big.Int).Mul(factor, augmented[i][k]))
					augmented[j][k].Mod(augmented[j][k], p)
				}
			}
		}
	}
	// fmt.Print("for2 end\n")

	// Extract the inverse matrix (right side of the augmented matrix)
	inverse := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		inverse[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			inverse[i][j] = new(big.Int).Set(augmented[i][n+j])
		}
	}
	// fmt.Print("for3 end\n")

	return inverse, nil
}

func PrintMatrix(matrix [][]*big.Int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%s ", val.String())
		}
		fmt.Println()
	}
}
