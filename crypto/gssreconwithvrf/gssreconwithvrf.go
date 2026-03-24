package gssreconwithvrf

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
)

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
func verifyRecursiveRP(AA *node.Node, shares []*big.Int, offset int) (int, *big.Int, error) {
	if AA.IsLeaf {
		if offset >= len(shares) {
			return 0, nil, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d)", AA.Idx, offset)
		}
		secret := shares[offset]
		return 1, secret, nil
	}

	// 2. Recursively collect all shares of child nodes for the non-leaf node
	childSecrets := make([]*big.Int, 0, AA.Childrennum)
	currentOffset := offset
	for i := 0; i < AA.Childrennum; i++ {
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

	coefficients, err := reconCoefficient(sharesVal)
	if err != nil {
		return 0, nil, fmt.Errorf("node [ID:%v]: reconstruction failed: %w", AA.Idx, err)
	}

	for i := AA.T; i < len(childSecrets); i++ {
		expectedVal := childSecrets[i]
		xVal := big.NewInt(int64(i + 1))

		calculatedVal := evaluatePolynomial(coefficients, xVal, bn128.Order)

		if expectedVal.Cmp(calculatedVal) != 0 {
			errMsg := fmt.Sprintf("VERIFICATION FAILED at Node [ID:%v]\n"+
				"  -> Mismatch at Logical Index [%d] (Real Node ID: %v)\n"+
				"  -> Fixed X Coordinate: %v\n"+
				"  -> Expected (from subtree): %v\n"+
				"  -> Calculated (from poly):  %v",
				AA.Idx, i, AA.Children[i].Idx, xVal, expectedVal, calculatedVal)
			return 0, nil, errors.New(errMsg)
		}
	}
	nodeSecret := coefficients[0]
	return currentOffset - offset, nodeSecret, nil
}

// Using the first t shares to recover the polynomial coefficient
func reconCoefficient(sharesVals []*big.Int) ([]*big.Int, error) {
	t := len(sharesVals)
	if t == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	xVals := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		xVals[i] = big.NewInt(int64(i + 1))
	}

	matrix := make([][]*big.Int, t)
	for i := 0; i < t; i++ {
		row := make([]*big.Int, t+1)
		xPow := big.NewInt(1)
		for j := 0; j < t; j++ {
			row[j] = new(big.Int).Set(xPow)
			xPow.Mul(xPow, xVals[i])
			xPow.Mod(xPow, bn128.Order)
		}
		row[t] = new(big.Int).Set(sharesVals[i])
		matrix[i] = row
	}

	//Gaussian elimination
	for col := 0; col < t; col++ {
		pivotRow := -1
		for r := col; r < t; r++ {
			if matrix[r][col].Sign() != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			return nil, fmt.Errorf("matrix is singular at column %d", col)
		}
		if pivotRow != col {
			matrix[col], matrix[pivotRow] = matrix[pivotRow], matrix[col]
		}
		pivotVal := matrix[col][col]
		pivotInv := new(big.Int).ModInverse(pivotVal, bn128.Order)
		if pivotInv == nil {
			return nil, fmt.Errorf("modular inverse failed")
		}
		for j := col; j <= t; j++ {
			matrix[col][j].Mul(matrix[col][j], pivotInv)
			matrix[col][j].Mod(matrix[col][j], bn128.Order)
		}
		for r := 0; r < t; r++ {
			if r != col && matrix[r][col].Sign() != 0 {
				factor := new(big.Int).Set(matrix[r][col])
				for j := col; j <= t; j++ {
					term := new(big.Int).Mul(factor, matrix[col][j])
					term.Mod(term, bn128.Order)

					matrix[r][j].Sub(matrix[r][j], term)
					matrix[r][j].Mod(matrix[r][j], bn128.Order)

					if matrix[r][j].Sign() < 0 {
						matrix[r][j].Add(matrix[r][j], bn128.Order)
					}
				}
			}
		}
	}

	//
	coefficients := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		val := new(big.Int).Set(matrix[i][t])
		if val.Sign() < 0 {
			val.Add(val, bn128.Order)
		}
		coefficients[i] = val
	}
	return coefficients, nil
}

// Method 2: Recursively verify child shares of non-leaf node using RScode from bottom to up
func RecurRSCode(AA *node.Node, shares []*big.Int) (bool, error) {
	if AA == nil {
		return false, errors.New("AA is empty")
	}
	_, _, err := verifyRecursiveRS(AA, shares, 0)
	if err != nil {
		return false, err
	}
	return true, nil
}
func verifyRecursiveRS(AA *node.Node, shares []*big.Int, offset int) (int, *big.Int, error) {
	// 1. Jugde whether is leaf node
	if AA.IsLeaf {
		if offset >= len(shares) {
			return 0, nil, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d)", AA.Idx, offset)
		}
		secret := shares[offset]
		// Leaf nodes do not require RS verification and directly the share value
		return 1, secret, nil
	}

	// 2.Non-leaf nodes: The secret to recursively collecting all child nodes
	childSecrets := make([]*big.Int, 0, AA.Childrennum)
	currentOffset := offset
	for i := 0; i < AA.Childrennum; i++ {
		if i >= len(AA.Children) || AA.Children[i] == nil {
			return 0, nil, fmt.Errorf("node [ID:%v]: missing child at index %d", AA.Idx, i)
		}
		consumed, childSecret, err := verifyRecursiveRS(AA.Children[i], shares, currentOffset)
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
	if !rscodeVerify(childSecrets, k) {
		return 0, nil, fmt.Errorf("node [ID:%v]: RS Code verification failed (probability check)", AA.Idx)
	}

	// 4. After successful verification, extract the secret of the current node for use by the upper layer.
	// By reconstructing using the first k points, a unique constant term can be obtained
	sharesForRecon := childSecrets[:k]
	coefficients, err := reconCoefficient(sharesForRecon)
	if err != nil {
		return 0, nil, fmt.Errorf("node [ID:%v]: reconstruction failed: %w", AA.Idx, err)
	}
	nodeSecret := coefficients[0]
	return currentOffset - offset, nodeSecret, nil
}

// SCRAPE: Scalable Randomness Attest by Public Entities
// Utilize the dual code C_perp
// if a set of shares is valid，for any c_perp in C_perp， <shares, c_perp> = 0
// C_perp from with a polynomail f(x) (with deg f(x) <= n-k-1),c_perp=(v1*f(1), ..., vn*f(n))
func rscodeVerify(shares []*big.Int, k int) bool {
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

// Method 3.1:
// GenerateSparseMatrix: Generate a global sparse parity check matrix H
// For each (n, t) node in the tree, construct an n x t Vandermonde matrix V
// Calculate its left null space basis vectors.
// These basis vectors form the rows of matrix H, satisfying H * shares = 0.
// Returns: [][]*big.Int (number of rows = total number of constraints, number of columns = total number of leaves)
func GenerateSparseMatrix(AA *node.Node) ([][]*big.Int, error) {
	if AA == nil {
		return nil, errors.New("access tree is nil")
	}
	totalLeaves := countLeaves(AA)
	if totalLeaves == 0 {
		return [][]*big.Int{}, nil
	}
	var allRows [][]*big.Int
	_, err := buildMatrixRecursive(AA, 0, &allRows, totalLeaves)
	if err != nil {
		return nil, err
	}
	return allRows, nil
}
func countLeaves(n *node.Node) int {
	if n == nil {
		return 0
	}
	if n.IsLeaf {
		return 1
	}
	sum := 0
	for _, child := range n.Children {
		sum += countLeaves(child)
	}
	return sum
}

// getLagrangeCoefficientsAtZero: Compute the Lagrange coefficient vector lambda
func getLagrangeCoefficientsAtZero(subTreeRoot *node.Node) ([]*big.Int, error) {
	m := countLeaves(subTreeRoot)
	if m == 0 {
		return nil, fmt.Errorf("subtree has no leaves")
	}

	order := bn128.Order
	lambdas := make([]*big.Int, m)

	//X Point: 1, 2, ..., m
	xs := make([]*big.Int, m)
	for i := 0; i < m; i++ {
		xs[i] = big.NewInt(int64(i + 1))
	}

	// Calculate the Lagrange coefficient at each position L_i(0)
	for i := 0; i < m; i++ {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for j := 0; j < m; j++ {
			if i == j {
				continue
			}
			// Numerator: (0 - x_j)
			termNum := new(big.Int).Neg(xs[j])
			termNum.Mod(termNum, order)
			numerator.Mul(numerator, termNum).Mod(numerator, order)

			// Denominator: (x_i - x_j)
			termDen := new(big.Int).Sub(xs[i], xs[j])
			termDen.Mod(termDen, order)
			denominator.Mul(denominator, termDen).Mod(denominator, order)
		}

		denInv := new(big.Int).ModInverse(denominator, order)
		if denInv == nil {
			return nil, fmt.Errorf("failed to compute modular inverse for Lagrange coefficient")
		}

		lam := new(big.Int).Mul(numerator, denInv)
		lam.Mod(lam, order)
		lambdas[i] = lam
	}

	return lambdas, nil
}
func buildMatrixRecursive(n *node.Node, currentOffset int, allRows *[][]*big.Int, totalCols int) (int, error) {
	// If leaf node，occupies 1 column
	if n.IsLeaf {
		return 1, nil
	}

	// 1. Determine the starting position of the node in the global matrix
	childOffsets := make([]int, len(n.Children))
	currentChildOffset := currentOffset

	for i, child := range n.Children {
		consumed, err := buildMatrixRecursive(child, currentChildOffset, allRows, totalCols)
		if err != nil {
			return 0, err
		}
		childOffsets[i] = currentChildOffset
		currentChildOffset += consumed
	}

	nCount := len(n.Children)
	tThreshold := n.T

	// If n <= t, there are no redundant constraints.
	if nCount <= tThreshold {
		return currentChildOffset - currentOffset, nil
	}

	// 2. Calculate the Null Space basis vectors of the current layer.
	//  sum(v[i] * S_child[i]) = 0
	nullSpaceBasis, err := computeVandermondeNullSpace(nCount, tThreshold)
	if err != nil {
		return 0, err
	}

	// 3. Transfer local constraints into global leaf constraints
	for _, vector := range nullSpaceBasis {
		row := make([]*big.Int, totalCols)
		for i := 0; i < totalCols; i++ {
			row[i] = big.NewInt(0)
		}
		for i, coeff := range vector {
			if coeff.Sign() == 0 {
				continue
			}

			child := n.Children[i]
			startIdx := childOffsets[i]

			if child.IsLeaf {
				row[startIdx] = new(big.Int).Set(coeff)
			} else {
				lambdas, err := getLagrangeCoefficientsAtZero(child)
				if err != nil {
					return 0, err
				}
				for k, lam := range lambdas {
					globalIdx := startIdx + k
					if globalIdx >= totalCols {
						return 0, fmt.Errorf("index out of bounds: %d >= %d", globalIdx, totalCols)
					}
					term := new(big.Int).Mul(coeff, lam)
					term.Mod(term, bn128.Order)
					row[globalIdx].Add(row[globalIdx], term)
					row[globalIdx].Mod(row[globalIdx], bn128.Order)
				}
			}
		}
		*allRows = append(*allRows, row)
	}
	return currentChildOffset - currentOffset, nil
}

// computeVandermondeNullSpace:
// Computes the basis of the left null space by reducing the transposed Vandermonde matrix
// to its Reduced Row Echelon Form (RREF) via Gauss-Jordan elimination
func computeVandermondeNullSpace(n, t int) ([][]*big.Int, error) {
	if t >= n {
		return [][]*big.Int{}, nil
	}
	VT := make([][]*big.Int, t)
	for j := 0; j < t; j++ {
		VT[j] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			x := big.NewInt(int64(i + 1))
			VT[j][i] = new(big.Int).Exp(x, big.NewInt(int64(j)), bn128.Order)
		}
	}
	matrix := make([][]*big.Int, t)
	for i := 0; i < t; i++ {
		matrix[i] = make([]*big.Int, n)
		copy(matrix[i], VT[i])
	}

	pivotCols := []int{}
	row := 0

	for col := 0; col < n && row < t; col++ {
		pivotRow := -1
		for r := row; r < t; r++ {
			if matrix[r][col].Sign() != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			continue
		}
		if pivotRow != row {
			matrix[row], matrix[pivotRow] = matrix[pivotRow], matrix[row]
		}
		pivotVal := matrix[row][col]
		pivotInv := new(big.Int).ModInverse(pivotVal, bn128.Order)
		if pivotInv == nil {
			return nil, errors.New("modular inverse failed in Vandermonde null space computation")
		}

		for c := 0; c < n; c++ {
			matrix[row][c].Mul(matrix[row][c], pivotInv).Mod(matrix[row][c], bn128.Order)
		}
		for r := 0; r < t; r++ {
			if r != row && matrix[r][col].Sign() != 0 {
				factor := new(big.Int).Set(matrix[r][col])
				for c := 0; c < n; c++ {
					term := new(big.Int).Mul(factor, matrix[row][c])
					term.Mod(term, bn128.Order)
					matrix[r][c].Sub(matrix[r][c], term)
					matrix[r][c].Mod(matrix[r][c], bn128.Order)
					if matrix[r][c].Sign() < 0 {
						matrix[r][c].Add(matrix[r][c], bn128.Order)
					}
				}
			}
		}
		pivotCols = append(pivotCols, col)
		row++
	}

	rank := len(pivotCols)
	numFreeVars := n - rank
	if numFreeVars == 0 {
		return [][]*big.Int{}, nil
	}
	isPivot := make(map[int]bool)
	for _, pc := range pivotCols {
		isPivot[pc] = true
	}
	freeCols := []int{}
	for c := 0; c < n; c++ {
		if !isPivot[c] {
			freeCols = append(freeCols, c)
		}
	}
	basis := make([][]*big.Int, numFreeVars)
	for i, freeColIdx := range freeCols {
		vec := make([]*big.Int, n)
		for k := 0; k < n; k++ {
			vec[k] = big.NewInt(0)
		}
		vec[freeColIdx] = big.NewInt(1)
		for r := 0; r < rank; r++ {
			pCol := pivotCols[r]
			coeff := matrix[r][freeColIdx]
			if coeff.Sign() != 0 {
				val := new(big.Int).Neg(coeff)
				val.Mod(val, bn128.Order)
				if val.Sign() < 0 {
					val.Add(val, bn128.Order)
				}
				vec[pCol] = val
			}
		}
		basis[i] = vec
	}
	return basis, nil
}

// Method 3.2: Parity-check Matrix
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
