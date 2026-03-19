// Matrix Operations
package opmatrix

import (
	"fmt"
	"math/big"

	bn128 "pvgss/bn128"
)

func MultiplyMatrix(A, B [][]*big.Int) ([][]*big.Int, error) {
	//  Get the dimensions of A and B
	n := len(A)    // number of rows in A
	m := len(A[0]) // number of columns in A (also number of rows in B)
	p := len(B[0]) //number of columns of B

	// Check
	if len(B) != m {
		return nil, fmt.Errorf("矩阵 A 的列数和矩阵 B 的行数不匹配")
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
			// C[i][j] = A[i][k] * B[k][j]  (from k0 to m-1)
			for k := 0; k < m; k++ {
				temp := new(big.Int)
				temp.Mul(A[i][k], B[k][j]) // A[i][k] * B[k][j]
				C[i][j].Add(C[i][j], temp).Mod(C[i][j], bn128.Order)
				// C[i][j].Add(C[i][j], temp)
			}
		}
	}

	return C, nil
}

func SetToMatrix(set []*big.Int) [][]*big.Int {
	if set == nil {
		return nil
	}

	matrix := make([][]*big.Int, len(set))

	for i := 0; i < len(set); i++ {
		matrix[i] = make([]*big.Int, 1)
		matrix[i][0] = set[i]
	}
	return matrix
}

func IsZeroMatrixMod(matrix [][]*big.Int) bool {
	if matrix == nil {
		return true
	}

	zero := big.NewInt(0)
	temp := new(big.Int) // 复用对象避免频繁分配

	for _, row := range matrix {
		for _, val := range row {
			if val == nil {
				return false
			}
			// temp = val % order
			temp.Mod(val, bn128.Order)

			if temp.Cmp(zero) != 0 {
				return false
			}
		}
	}
	return true
}

func PrintMatrix(matrix [][]*big.Int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%s ", val.String())
		}
		fmt.Println()
	}
}

// 1.Generate the transpose of the LSSS matrix
// 2.Gaussian elimination:Reduce to the simplest matrix
// 3.Transform into a system of equations
// 4.Identify free variables
// 5.Assigning values ​​to free variables
func GenerateParityMatrix(M [][]*big.Int) [][]*big.Int {
	if len(M) == 0 || len(M[0]) == 0 {
		return [][]*big.Int{}
	}
	n := len(M)
	d := len(M[0])

	modSub := func(a, b *big.Int) *big.Int {
		res := new(big.Int).Sub(a, b)
		res.Mod(res, bn128.Order)
		if res.Sign() < 0 {
			res.Add(res, bn128.Order)
		}
		return res
	}

	// 1. Generate the transpose of the LSSS matrix M -> A (d x n)
	// A[i][j] = M[j][i]
	A := make([][]*big.Int, d)
	for i := 0; i < d; i++ {
		A[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			A[i][j] = new(big.Int).Set(M[j][i])
			A[i][j].Mod(A[i][j], bn128.Order)
		}
	}

	// 2.Gauss-Jordan Elimination: reduce to the simplest matrix
	pivotCols := []int{}
	currentRow := 0

	// 3.Transform into a system of equations and identify free variables
	for col := 0; col < n && currentRow < d; col++ {
		pivotRow := -1
		for r := currentRow; r < d; r++ {
			if A[r][col].Sign() != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			continue
		}
		if pivotRow != currentRow {
			A[currentRow], A[pivotRow] = A[pivotRow], A[currentRow]
		}
		pivotVal := A[currentRow][col]
		invPivot := new(big.Int).ModInverse(pivotVal, bn128.Order)
		if invPivot == nil {
			panic("Fail to compute ModInverse: Matrix singular or P not prime?")
		}

		for c := 0; c < n; c++ {
			A[currentRow][c].Mul(A[currentRow][c], invPivot).Mod(A[currentRow][c], bn128.Order)
		}
		for r := 0; r < d; r++ {
			if r != currentRow && A[r][col].Sign() != 0 {
				factor := A[r][col]
				for c := 0; c < n; c++ {
					// term = factor * A[currentRow][c]
					term := new(big.Int).Mul(factor, A[currentRow][c])
					term.Mod(term, bn128.Order)
					A[r][c] = modSub(A[r][c], term)
				}
			}
		}

		pivotCols = append(pivotCols, col)
		currentRow++
	}

	rank := len(pivotCols)
	numFreeVars := n - rank

	// Mark the pivot column
	isPivotCol := make(map[int]bool)
	for _, pc := range pivotCols {
		isPivotCol[pc] = true
	}

	// Collect free variable column indexes
	freeCols := []int{}
	for c := 0; c < n; c++ {
		if !isPivotCol[c] {
			freeCols = append(freeCols, c)
		}
	}

	// 5. Construct the parity check matrix H (numFreeVars x n)
	H := make([][]*big.Int, numFreeVars)

	for i, freeColIdx := range freeCols {
		H[i] = make([]*big.Int, n)
		for k := 0; k < n; k++ {
			H[i][k] = big.NewInt(0)
		}
		H[i][freeColIdx].Set(big.NewInt(1))

		for row := 0; row < rank; row++ {
			pivotColIdx := pivotCols[row]
			coeff := A[row][freeColIdx]
			val := new(big.Int).Neg(coeff)
			val.Mod(val, bn128.Order)
			if val.Sign() < 0 {
				val.Add(val, bn128.Order)
			}
			H[i][pivotColIdx].Set(val)
		}
	}
	return H
}
