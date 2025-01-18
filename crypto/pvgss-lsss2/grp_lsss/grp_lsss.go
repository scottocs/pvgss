package grp_lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-lsss2/lsss"
	"pvgss/crypto/pvgss-sss/gss"
)

func GrpLSSSShare(S *bn128.G1, AA *gss.Node) ([]*bn128.G1, error) {
	matrix := lsss.Convert(AA)
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
	lambdas, _ := lsss.MultiplyMatrix(matrix, v2)
	for i, lambda := range lambdas {
		shares[i] = new(bn128.G1).ScalarMult(S, lambda[0])
	}
	return shares, nil
}

func GrpLSSSRecon(AA *gss.Node, shares []*bn128.G1, I []int) (*bn128.G1, error) {
	matrix := lsss.Convert(AA)
	rows := len(I)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < len(I); i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ := lsss.GaussJordanInverse(recMatrix)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)
	w, _ := lsss.MultiplyMatrix(one, invRecMatrix)
	reconS := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(w[0]); i++ {
		reconS.Add(reconS, new(bn128.G1).ScalarMult(shares[i], w[0][i]))
	}
	return reconS, nil
}
