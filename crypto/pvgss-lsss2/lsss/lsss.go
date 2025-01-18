package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-sss/gss"
)

func LSSSShare(s *big.Int, AA *gss.Node) ([]*big.Int, error) {
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
	lambdas, _ := MultiplyMatrix(matrix, v2)
	// PrintMatrix(lambdas)
	for i, lambda := range lambdas {
		shares[i] = lambda[0]
	}
	return shares, nil
}

func LSSSRecon(AA *gss.Node, shares []*big.Int, I []int) (*big.Int, error) {
	matrix := Convert(AA)
	rows := len(I)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < len(I); i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ := GaussJordanInverse(recMatrix)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)
	w, _ := MultiplyMatrix(one, invRecMatrix)
	shares2 := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		shares2[i] = []*big.Int{shares[i]}
	}
	reconS, _ := MultiplyMatrix(w, shares2)
	s := reconS[0][0]
	return s, nil
}

// 提取并剥离第一个阈值结构
func ExtractFirstThreshold(root *gss.Node) (*gss.Node, []*gss.Node, int, int) {
	if root == nil {
		return nil, nil, 0, 0
	}

	// 如果是叶子节点，则没有阈值结构
	if root.IsLeaf {
		return nil, []*gss.Node{root}, 0, 0
	}

	// 处理第一个非叶子节点，提取其阈值结构
	t := root.T
	n := root.Childrennum
	children := root.Children

	// 返回当前节点的阈值结构，以及其子节点
	return &gss.Node{
		IsLeaf:      false,
		Children:    nil, // 这个层的结构被剥离
		Childrennum: n,
		T:           t,
		Idx:         root.Idx,
	}, children, t, n
}

func Convert(F_A *gss.Node) [][]*big.Int {
	// 初始化 L 和 M
	L := []*gss.Node{F_A}
	M := [][]*big.Int{{big.NewInt(1)}} // 修改为指针类型
	m, d := 1, 1
	z := 1 // 控制循环

	for z != 0 {
		z = 0
		i := 1
		var n, t int
		var threshold *gss.Node
		var remainingStructure []*gss.Node

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
			L1 := make([]*gss.Node, len(L))
			copy(L1, L)
			M1 := make([][]*big.Int, len(M))
			for i := range M {
				M1[i] = make([]*big.Int, len(M[i]))
				copy(M1[i], M[i])
			}

			m1, d1 := m, d
			// 重新初始化 M 和 L
			M = make([][]*big.Int, m1+m2-1)
			for i := range M {
				M[i] = make([]*big.Int, d1+d2-1)
				for j := range M[i] {
					M[i][j] = big.NewInt(0) // 初始化为指针类型 0
				}
			}
			L = make([]*gss.Node, m1+m2-1)

			// 更新 M 和 L
			for u := 0; u < z-1; u++ {
				L[u] = L1[u]
				for v := 0; v < d1; v++ {
					M[u][v] = M1[u][v]
				}
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(0) // 初始化为指针类型 0
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
					x = (x * a) % 1000000
				}
			}

			for u := z + m2 - 1; u < m1+m2-1; u++ {
				L[u] = L1[u-m2+1]
				for v := 0; v < d1; v++ {
					M[u][v] = M1[u-m2+1][v]
				}
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(0) // 初始化为指针类型 0
				}
			}

			m, d = m1+m2-1, d1+d2-1
		}
	}

	// 打印最终矩阵 M
	// PrintMatrix(M)
	return M
}

func MultiplyMatrix(A, B [][]*big.Int) ([][]*big.Int, error) {
	// 获取 A 和 B 的维度
	n := len(A)    // A 的行数
	m := len(A[0]) // A 的列数（也是 B 的行数）
	p := len(B[0]) // B 的列数

	// 检查矩阵 A 和 B 是否可乘
	if len(B) != m {
		return nil, fmt.Errorf("矩阵 A 的列数和矩阵 B 的行数不匹配")
	}

	// 初始化结果矩阵 C (n * p)，所有元素初始化为 big.NewInt(0)
	C := make([][]*big.Int, n)
	for i := range C {
		C[i] = make([]*big.Int, p)
		for j := range C[i] {
			C[i][j] = big.NewInt(0) // 初始化为 0
		}
	}

	// 矩阵乘法计算
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			// C[i][j] = A[i][k] * B[k][j]  (k从0到m-1)
			for k := 0; k < m; k++ {
				// 临时存储 C[i][j] 的值
				temp := new(big.Int)
				temp.Mul(A[i][k], B[k][j])                           // A[i][k] * B[k][j]
				C[i][j].Add(C[i][j], temp).Mod(C[i][j], bn128.Order) // 累加到 C[i][j]
				// C[i][j].Add(C[i][j], temp)
			}
		}
	}

	return C, nil
}

// GaussJordanInverse computes the inverse of matrix A using Gauss-Jordan elimination.
// It returns the inverse matrix if it exists, otherwise returns an error.
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

	// Extract the inverse matrix (right side of the augmented matrix)
	inverse := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		inverse[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			inverse[i][j] = new(big.Int).Set(augmented[i][n+j])
		}
	}

	return inverse, nil
}

// 打印矩阵
func PrintMatrix(matrix [][]*big.Int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%s ", val.String())
		}
		fmt.Println()
	}
}

// Convert 将阈值结构转换为矩阵
// func Convert(F_A *Node) [][]big.Int {
// 	// 初始化 L 和 M
// 	L := []*Node{F_A}
// 	M := [][]big.Int{{*big.NewInt(1)}}
// 	m, d := 1, 1
// 	z := 1 // 控制循环

// 	for z != 0 {
// 		z = 0
// 		i := 1
// 		var n, t int
// 		var threshold *Node
// 		var remainingStructure []*Node

// 		for i <= m && z == 0 {
// 			currentStructure := L[i-1]
// 			threshold, remainingStructure, t, n = ExtractFirstThreshold(currentStructure)

// 			if threshold != nil {
// 				z = i
// 				break
// 			}
// 			i++
// 		}

// 		if z != 0 {
// 			// F_z := L[z-1]
// 			m2, d2 := n, t
// 			L2 := remainingStructure
// 			L1 := make([]*Node, len(L))
// 			copy(L1, L)
// 			M1 := make([][]big.Int, len(M))
// 			for i := range M {
// 				M1[i] = make([]big.Int, len(M[i]))
// 				copy(M1[i], M[i])
// 			}

// 			m1, d1 := m, d
// 			// 重新初始化 M 和 L
// 			M = make([][]big.Int, m1+m2-1)
// 			for i := range M {
// 				M[i] = make([]big.Int, d1+d2-1)
// 			}
// 			L = make([]*Node, m1+m2-1)

// 			// 更新 M 和 L
// 			for u := 0; u < z-1; u++ {
// 				L[u] = L1[u]
// 				for v := 0; v < d1; v++ {
// 					M[u][v] = M1[u][v]
// 				}
// 				for v := d1; v < d1+d2-1; v++ {
// 					M[u][v] = *big.NewInt(0)
// 				}
// 			}

// 			for u := z - 1; u < z+m2-1; u++ {
// 				L[u] = L2[u-z+1]
// 				for v := 0; v < d1; v++ {
// 					M[u][v] = M1[z-1][v]
// 				}
// 				a, x := (u+1)-(z-1), (u+1)-(z-1)
// 				for v := d1; v < d1+d2-1; v++ {
// 					M[u][v] = *big.NewInt(int64(x))
// 					x = (x * a) % 1000000
// 				}
// 			}

// 			for u := z + m2 - 1; u < m1+m2-1; u++ {
// 				L[u] = L1[u-m2+1]
// 				for v := 0; v < d1; v++ {
// 					M[u][v] = M1[u-m2+1][v]
// 				}
// 				for v := d1; v < d1+d2-1; v++ {
// 					M[u][v] = *big.NewInt(0)
// 				}
// 			}

// 			m, d = m1+m2-1, d1+d2-1
// 		}
// 	}

// 	// 打印最终矩阵 M
// 	PrintMatrix(M)
// 	// fmt.Println("Converted Matrix M:")
// 	// for _, row := range M {
// 	// 	fmt.Println(row)
// 	// }
// 	return M
// }
