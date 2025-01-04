// Shamir's secret sharing on G
package grp_sss

import (
	"crypto/rand"
	"math/big"
	bn128 "pvgss/bn128"
)

func GrpShare(S *bn128.G1, n, t int) ([]*bn128.G1, error) {
	// 定义曲线阶数
	order := bn128.Order

	// 生成多项式的随机系数
	cofficients := make([]*big.Int, t)
	cofficients[0] = new(big.Int).SetInt64(0) // 初始化为0
	for i := 1; i < t; i++ {
		cofficients[i], _ = rand.Int(rand.Reader, order)
	}
	// 生成关于秘密的份额
	shares := make([]*bn128.G1, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		ployres := evaluatePolynomial(cofficients, x, order)
		temp := new(bn128.G1).ScalarBaseMult(ployres)
		shares[i] = new(bn128.G1).Add(S, temp)
	}
	return shares, nil
}

// evaluatePolynomial 在给定的 x 处计算多项式的值
func evaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, order)
	}

	return result
}

// 预计算拉格朗日系数,其中I是Q中份额对应的下标
func PrecomputeLagrangeCoefficients(I []*big.Int) ([]*big.Int, error) {
	lambdas := make([]*big.Int, len(I))
	k := len(I)
	order := bn128.Order
	// 计算所有拉格朗日系数
	for i := 0; i < k; i++ {
		lambda_i := big.NewInt(1)
		for j := 0; j < k; j++ {
			if i != j {
				num := new(big.Int).Neg(I[j])

				den := new(big.Int).Sub(I[i], I[j])
				den.ModInverse(den, order)

				lambda_i.Mul(lambda_i, num)
				lambda_i.Mul(lambda_i, den)
				lambda_i.Mod(lambda_i, order)
			}
		}
		lambdas[i] = lambda_i
	}
	return lambdas, nil
}

func GrpRecon(Q []*bn128.G1, I []*big.Int) (*bn128.G1, error) {
	// I := make([]*big.Int, len(Q))
	// for i := 0; i < len(Q); i++ {
	// 	I[i] = big.NewInt(int64(i + 1))
	// }
	lambdas, _ := PrecomputeLagrangeCoefficients(I)
	Secret := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(Q); i++ {
		lambda_i := lambdas[i]
		temp := new(bn128.G1).ScalarMult(Q[i], lambda_i)
		Secret.Add(Secret, temp)
	}
	return Secret, nil
}
