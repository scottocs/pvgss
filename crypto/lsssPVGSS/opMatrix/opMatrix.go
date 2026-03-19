// Matrix Operations
package opMatrix

import (
	"math/big"

	bn128 "pvgss/bn128"

	lib "github.com/fentec-project/gofe/abe"
)

// Transfer MSP as Matrix
func MSPtoMatrix(msp lib.MSP) [][]*big.Int {
	rows := msp.Mat.Rows()
	cols := msp.Mat.Cols()
	matrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			matrix[i][j] = msp.Mat[i][j].Mod(msp.Mat[i][j], bn128.Order)
		}
	}
	return matrix
}
