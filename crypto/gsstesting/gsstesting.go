package gsstesting

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
	"pvgss/crypto/transcript"
)

var lagrangeCache sync.Map
var dualWeightCache sync.Map

type lagrangeCacheKey struct {
	k      int
	target int
}

// Method 1: Restore the polynomial layer by layer from bottom to top
// Each polynomial is used to verify last n-t child nodes.
func ReconPolynomial(AA *node.Node, shares []*big.Int) (bool, error) {
	if AA == nil {
		return false, errors.New("AA is empty")
	}
	_, _, err := verifyRecursiveRP(AA, shares, 0)
	if err != nil {
		return false, err
	}
	return true, nil
}

func GSSTest(AA *node.Node, shares []*big.Int) (*big.Int, bool, error) {
	return GSSTestExact(AA, shares)
}

func GSSTestExact(AA *node.Node, shares []*big.Int) (*big.Int, bool, error) {
	if AA == nil {
		return nil, false, errors.New("AA is empty")
	}
	consumed, rootSecret, err := verifyRecursiveRP(AA, shares, 0)
	if err != nil {
		return nil, false, err
	}
	if consumed != len(shares) {
		return nil, false, fmt.Errorf("share length mismatch: consumed %d, got %d", consumed, len(shares))
	}
	return rootSecret, true, nil
}

func GSSTestDual(AA *node.Node, shares []*big.Int) (*big.Int, bool, error) {
	if AA == nil {
		return nil, false, errors.New("AA is empty")
	}
	seed := transcript.DualTestSeed(AA, shares, nil, nil, nil)
	return GSSTestDualWithSeed(AA, shares, seed)
}

func GSSTestDualWithSeed(AA *node.Node, shares []*big.Int, seed []byte) (*big.Int, bool, error) {
	if AA == nil {
		return nil, false, errors.New("AA is empty")
	}
	consumed, rootSecret, err := verifyRecursiveRS(AA, shares, 0, seed, nil)
	if err != nil {
		return nil, false, err
	}
	if consumed != len(shares) {
		return nil, false, fmt.Errorf("share length mismatch: consumed %d, got %d", consumed, len(shares))
	}
	return rootSecret, true, nil
}

func verifyRecursiveRP(AA *node.Node, shares []*big.Int, offset int) (int, *big.Int, error) {
	if AA.IsLeaf {
		if offset >= len(shares) {
			return 0, nil, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d)", AA.Idx, offset)
		}
		secret := shares[offset]
		return 1, secret, nil
	}

	// 2. Recursively collect all shares of child nodes for the non-leaf node
	childSecrets := make([]*big.Int, 0, AA.ChildrenNum)
	currentOffset := offset
	for i := 0; i < AA.ChildrenNum; i++ {
		if i >= len(AA.Children) {
			return 0, nil, fmt.Errorf("node [ID:%v]: children count mismatch", AA.Idx)
		}
		child := AA.Children[i]
		consumed, childSecret, err := verifyRecursiveRP(child, shares, currentOffset)
		if err != nil {
			return 0, nil, err
		}
		childSecrets = append(childSecrets, childSecret)
		currentOffset += consumed
	}
	if len(childSecrets) < AA.T {
		return 0, nil, fmt.Errorf("node [ID:%v]: insufficient child secrets (%d < %d)", AA.Idx, len(childSecrets), AA.T)
	}
	sharesVal := childSecrets[:AA.T]

	nodeSecret, err := interpolateAt(sharesVal, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("node [ID:%v]: reconstruction failed: %w", AA.Idx, err)
	}

	for i := AA.T; i < len(childSecrets); i++ {
		expectedVal := childSecrets[i]

		calculatedVal, err := interpolateAt(sharesVal, i+1)
		if err != nil {
			return 0, nil, fmt.Errorf("node [ID:%v]: interpolation failed: %w", AA.Idx, err)
		}

		if expectedVal.Cmp(calculatedVal) != 0 {
			errMsg := fmt.Sprintf("VERIFICATION FAILED at Node [ID:%v]\n"+
				"  -> Mismatch at Logical Index [%d] (Real Node ID: %v)\n"+
				"  -> Fixed X Coordinate: %v\n"+
				"  -> Expected (from subtree): %v\n"+
				"  -> Calculated (from poly):  %v",
				AA.Idx, i, AA.Children[i].Idx, i+1, expectedVal, calculatedVal)
			return 0, nil, errors.New(errMsg)
		}
	}
	return currentOffset - offset, nodeSecret, nil
}

// Method 2: Recursively verify child shares of non-leaf node using RScode from bottom to up
func RecurRSCode(AA *node.Node, shares []*big.Int) (bool, error) {
	if AA == nil {
		return false, errors.New("AA is empty")
	}
	seed := transcript.DualTestSeed(AA, shares, nil, nil, nil)
	_, _, err := verifyRecursiveRS(AA, shares, 0, seed, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}
func verifyRecursiveRS(AA *node.Node, shares []*big.Int, offset int, seed, path []byte) (int, *big.Int, error) {
	// 1. Judge whether is leaf node
	if AA.IsLeaf {
		if offset >= len(shares) {
			return 0, nil, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d)", AA.Idx, offset)
		}
		secret := shares[offset]
		// Leaf nodes do not require RS verification and directly the share value
		return 1, secret, nil
	}

	// 2.Non-leaf nodes: The secret to recursively collecting all child nodes
	childSecrets := make([]*big.Int, 0, AA.ChildrenNum)
	currentOffset := offset
	for i := 0; i < AA.ChildrenNum; i++ {
		if i >= len(AA.Children) || AA.Children[i] == nil {
			return 0, nil, fmt.Errorf("node [ID:%v]: missing child at index %d", AA.Idx, i)
		}
		var childIndex [4]byte
		binary.BigEndian.PutUint32(childIndex[:], uint32(i))
		childPath := append(append([]byte{}, path...), childIndex[:]...)
		consumed, childSecret, err := verifyRecursiveRS(AA.Children[i], shares, currentOffset, seed, childPath)
		if err != nil {
			return 0, nil, err
		}

		childSecrets = append(childSecrets, childSecret)
		currentOffset += consumed
	}

	n := len(childSecrets)
	k := AA.T
	if n < k {
		return 0, nil, fmt.Errorf("node [ID:%v]: insufficient child secrets (%d < %d)", AA.Idx, n, k)
	}

	// Invoke rscodeVerify algorithm to check all child shares whether is valid
	if !rscodeVerify(childSecrets, k, seed, path) {
		return 0, nil, fmt.Errorf("node [ID:%v]: RS Code verification failed (probability check)", AA.Idx)
	}

	// 4. After successful verification, extract the secret of the current node for use by the upper layer.
	// By reconstructing at zero using the first k points, a unique constant term can be obtained.
	nodeSecret, err := interpolateAt(childSecrets[:k], 0)
	if err != nil {
		return 0, nil, fmt.Errorf("node [ID:%v]: reconstruction failed: %w", AA.Idx, err)
	}
	return currentOffset - offset, nodeSecret, nil
}

// SCRAPE: Scalable Randomness Attest by Public Entities
// Utilize the dual code C_perp
// if a set of shares is valid，for any c_perp in C_perp， <shares, c_perp> = 0
// C_perp from with a polynomail f(x) (with deg f(x) <= n-k-1),c_perp=(v1*f(1), ..., vn*f(n))
func rscodeVerify(shares []*big.Int, k int, seed, path []byte) bool {
	n := len(shares)
	if n == k {
		//fmt.Printf("This is \"AND\" structure, skips the RSCode verification!\n")
		return true
	}
	if n <= k-1 {
		fmt.Printf("number of shares must be greater than threshold k for verification\n")
		return false
	}

	// Derive the random dual word from the complete response vector and node path.
	degF := n - k - 1

	fCoeffs := make([]*big.Int, degF+1)
	for i := 0; i <= degF; i++ {
		h := sha256.New()
		_, _ = h.Write([]byte("PVGSS-DUAL-NODE-v1"))
		_, _ = h.Write(seed)
		_, _ = h.Write(path)
		var coefficientIndex [4]byte
		binary.BigEndian.PutUint32(coefficientIndex[:], uint32(i))
		_, _ = h.Write(coefficientIndex[:])
		fCoeffs[i] = new(big.Int).SetBytes(h.Sum(nil))
		fCoeffs[i].Mod(fCoeffs[i], bn128.Order)
	}

	weights, err := dualBarycentricWeights(n)
	if err != nil {
		fmt.Printf("dual weight precomputation failed: %v\n", err)
		return false
	}

	// 3. Verify  <shares, cPerp>?=0
	innerProduct := big.NewInt(0)
	for i := 0; i < n; i++ {
		x_i := big.NewInt(int64(i + 1))
		fVal := evaluatePolynomial(fCoeffs, x_i, bn128.Order)
		term := new(big.Int).Mul(weights[i], fVal)
		term.Mod(term, bn128.Order)
		term.Mul(term, shares[i])
		term.Mod(term, bn128.Order)
		innerProduct.Add(innerProduct, term)
		innerProduct.Mod(innerProduct, bn128.Order)
	}
	if innerProduct.Cmp(big.NewInt(0)) != 0 {
		return false
	}

	return true
}

func interpolateAt(sharesVals []*big.Int, target int) (*big.Int, error) {
	coefficients, err := lagrangeCoefficients(len(sharesVals), target)
	if err != nil {
		return nil, err
	}
	value := big.NewInt(0)
	for i := range sharesVals {
		term := new(big.Int).Mul(coefficients[i], sharesVals[i])
		term.Mod(term, bn128.Order)
		value.Add(value, term)
		value.Mod(value, bn128.Order)
	}
	return value, nil
}

func lagrangeCoefficients(k, target int) ([]*big.Int, error) {
	if k == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	key := lagrangeCacheKey{k: k, target: target}
	if cached, ok := lagrangeCache.Load(key); ok {
		return cloneBigIntSlice(cached.([]*big.Int)), nil
	}
	coefficients := make([]*big.Int, k)
	x := big.NewInt(int64(target))
	for i := 1; i <= k; i++ {
		num := big.NewInt(1)
		den := big.NewInt(1)
		xi := big.NewInt(int64(i))
		for j := 1; j <= k; j++ {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(j))
			num.Mul(num, new(big.Int).Sub(x, xj))
			num.Mod(num, bn128.Order)
			den.Mul(den, new(big.Int).Sub(xi, xj))
			den.Mod(den, bn128.Order)
		}
		denInv := new(big.Int).ModInverse(den, bn128.Order)
		if denInv == nil {
			return nil, fmt.Errorf("modular inverse failed")
		}
		coefficients[i-1] = new(big.Int).Mul(num, denInv)
		coefficients[i-1].Mod(coefficients[i-1], bn128.Order)
	}
	lagrangeCache.Store(key, cloneBigIntSlice(coefficients))
	return coefficients, nil
}

func dualBarycentricWeights(n int) ([]*big.Int, error) {
	if cached, ok := dualWeightCache.Load(n); ok {
		return cloneBigIntSlice(cached.([]*big.Int)), nil
	}
	weights := make([]*big.Int, n)
	for i := 1; i <= n; i++ {
		den := big.NewInt(1)
		xi := big.NewInt(int64(i))
		for j := 1; j <= n; j++ {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(j))
			den.Mul(den, new(big.Int).Sub(xi, xj))
			den.Mod(den, bn128.Order)
		}
		denInv := new(big.Int).ModInverse(den, bn128.Order)
		if denInv == nil {
			return nil, fmt.Errorf("modular inverse failed")
		}
		weights[i-1] = denInv
	}
	dualWeightCache.Store(n, cloneBigIntSlice(weights))
	return weights, nil
}

func cloneBigIntSlice(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i := range values {
		out[i] = new(big.Int).Set(values[i])
	}
	return out
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
