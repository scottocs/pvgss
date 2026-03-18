// Shamir's secret sharing
package sss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
)

func Share(s *big.Int, n, t int) ([]*big.Int, error) {
	// Generate the random coefficients of the polynomial
	cofficients := make([]*big.Int, t)
	cofficients[0] = s
	for i := 1; i < t; i++ {
		cofficients[i], _ = rand.Int(rand.Reader, bn128.Order)
	}
	// Generate secret shares
	shares := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		shares[i] = evaluatePolynomial(cofficients, x, bn128.Order)
	}
	return shares, nil
}

// SCRAPE: Scalable Randomness Attest by Public Entities
// Utilize the dual code C_perp
// if a set of shares is valid，for any c_perp in C_perp， <shares, c_perp> = 0
// C_perp from with a polynomail f(x) (with deg f(x) <= n-k-1),c_perp=(v1*f(1), ..., vn*f(n))
func RSCodeVerify(shares []*big.Int, k int) bool {
	n := len(shares)
	if n == k {
		fmt.Printf("This is \"AND\" structure, skips the RSCode verification!\n")
		return true
	}
	if n <= k-1 {
		fmt.Printf("number of shares must be greater than threshold k for verification\n")
		return false
	}

	// 1. Generate f(x) with most (n-k-1) degree which is used to obtain c_perp
	degF := n - k - 1

	// Selects f(x) Coefficients: f_0, f_1, ..., f_degF
	fCoeffs := make([]*big.Int, degF+1)
	for i := 0; i <= degF; i++ {
		c, err := rand.Int(rand.Reader, bn128.Order)
		if err != nil {
			return false
		}
		fCoeffs[i] = c
	}

	//  c_perp = (y_1, y_2, ..., y_n), where y_i = v_i * f(i)
	// v_i = Product_{j!=i} (1 / (i - j))
	cPerp := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x_i := big.NewInt(int64(i + 1))
		denom := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			x_j := big.NewInt(int64(j + 1))
			diff := new(big.Int).Sub(x_i, x_j)
			denom.Mul(denom, diff)
			denom.Mod(denom, bn128.Order)
		}
		v_i := new(big.Int).ModInverse(denom, bn128.Order)
		if v_i == nil {
			fmt.Printf("modular inverse failed, q might not be prime or denom is 0\n")
			return false
		}

		// Compute f(x_i)
		fVal := evaluatePolynomial(fCoeffs, x_i, bn128.Order)

		// y_i = v_i * f(x_i)
		y_i := new(big.Int).Mul(v_i, fVal)
		y_i.Mod(y_i, bn128.Order)

		cPerp[i] = y_i
	}

	// 3. Verify  <shares, cPerp>?=0
	innerProduct := big.NewInt(0)
	for i := 0; i < n; i++ {
		term := new(big.Int).Mul(shares[i], cPerp[i])
		term.Mod(term, bn128.Order)
		innerProduct.Add(innerProduct, term)
		innerProduct.Mod(innerProduct, bn128.Order)
	}
	if innerProduct.Cmp(big.NewInt(0)) != 0 {
		return false
	}

	return true
}

func Recon(Q []*big.Int, I []*big.Int, threshold int) (*big.Int, error) {

	// 1. RS Code Verifiy
	if len(Q) < threshold {
		return nil, fmt.Errorf("not enough shares: got %d, need %d", len(Q), threshold)
	}
	isValid := RSCodeVerify(Q, threshold)

	if !isValid {
		return nil, errors.New("RSCode verification failed: invalid shares detected")
	}

	fmt.Printf("RSCode Verification pass!!!\n")

	//2.Reconstruct after pass the RSCode verification
	lambdas, _ := PrecomputeLagrangeCoefficients(I)
	secret := big.NewInt(0)
	for i := 0; i < threshold; i++ {
		lambda_i := lambdas[i]
		temp := new(big.Int).Mul(Q[i], lambda_i)
		secret.Add(secret, temp)
		secret.Mod(secret, bn128.Order)
	}
	return secret, nil
}

// evaluatePolynomial Compute the value of the polynomial at a given x
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

// Calculate the Lagrangian coefficients, where I is the index corresponding to the shares in Q
func PrecomputeLagrangeCoefficients(I []*big.Int) ([]*big.Int, error) {
	lambdas := make([]*big.Int, len(I))
	k := len(I)
	order := bn128.Order
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
