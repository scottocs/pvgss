package gssreconwithvrf

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bn128 "pvgss/bn128"
	"pvgss/crypto/ssspvgss/gss"
)

func ReconPolynomial(shares []*big.Int, t int) (bool, error) {
	if len(shares) < t {
		return false, fmt.Errorf("not enough shares: have %d, need %d", len(shares), t)
	}
	if t <= 0 {
		return false, fmt.Errorf("threshold t must be positive")
	}

	//sharesVals := append([]*big.Int{}, shares[:t]...)

	return true, nil
}

func reconCoefficient(sharesVals []*big.Int) ([]*big.Int, error) {
	t := len(sharesVals)

	// x 值生成 (假设是 1, 2, ..., t)
	xVals := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		xVals[i] = big.NewInt(int64(i + 1))
	}

	matrix := make([][]*big.Int, t)
	for i := 0; i < t; i++ {
		row := make([]*big.Int, t+1)
		xPow := big.NewInt(1) // x^0

		for j := 0; j < t; j++ {
			row[j] = new(big.Int).Set(xPow)

			// 计算下一个幂次
			xPow.Mul(xPow, xVals[i])
			xPow.Mod(xPow, bn128.Order)
		}

		// 【关键修复】这里必须深拷贝！不能直接引用 sharesVals[i]
		// 因为后面的高斯消元会修改 matrix[i][t]，如果这里是引用，就会破坏原始 sharesVals
		row[t] = new(big.Int).Set(sharesVals[i])

		matrix[i] = row
	}

	// ... 后续的高斯消元代码保持不变 ...
	// (你的消元逻辑本身是对的，只要输入数据没被污染)

	// ... (省略中间消元代码，保持原样) ...

	// 为了完整性，这里简单示意消元部分不需要动，只要上面的 row[t] 改了就行
	for col := 0; col < t; col++ {
		pivotRow := -1
		for r := col; r < t; r++ {
			if matrix[r][col].Sign() != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			return nil, fmt.Errorf("matrix is singular")
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
				factor := matrix[r][col]
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

// ShareInfo 用于存储局部计算所需的份额信息
type ShareInfo struct {
	GlobalCol int      // 全局列索引
	X         *big.Int // 局部 x 坐标
}

// DualMatrixGenerator 对偶矩阵生成器
type DualMatrixGenerator struct {
	Rows         [][]*big.Int // 【修改】直接存储整数矩阵
	TotalLeaves  int
	LeafIndexMap map[string]int
}

// NewDualMatrixGenerator 初始化生成器
func NewDualMatrixGenerator() *DualMatrixGenerator {
	return &DualMatrixGenerator{
		Rows:         make([][]*big.Int, 0),
		LeafIndexMap: make(map[string]int),
	}
}

// CollectLeavesAndMap 遍历树，统计叶子并建立映射
func CollectLeavesAndMap(g *DualMatrixGenerator, root *gss.Node) {
	g.TotalLeaves = 0
	collectLeavesRecursive(g, root)
}

func collectLeavesRecursive(g *DualMatrixGenerator, node *gss.Node) {
	if node.IsLeaf {
		key := node.Idx.String()
		if _, exists := g.LeafIndexMap[key]; !exists {
			g.LeafIndexMap[key] = g.TotalLeaves
			g.TotalLeaves++
		}
		return
	}
	for _, child := range node.Children {
		collectLeavesRecursive(g, child)
	}
}

// lcmOf 计算最小公倍数
func lcmOf(a, b *big.Int) *big.Int {
	if a.Sign() == 0 || b.Sign() == 0 {
		return big.NewInt(1)
	}
	g := new(big.Int).GCD(nil, nil, a, b)
	temp := new(big.Int).Mul(a, b)
	return temp.Div(temp, g)
}

// Generate 遍历访问树并生成对偶矩阵的整数行
// 直接作为入口函数，同时承担递归任务
func Generate(g *DualMatrixGenerator, node *gss.Node) {
	// 终止条件：如果是叶子节点，直接返回
	if node.IsLeaf {
		return
	}

	var shares []ShareInfo
	currentX := big.NewInt(1)

	// 1. 收集当前节点直接连接的叶子子节点
	hasDirectLeafChildren := false
	for _, child := range node.Children {
		if child.IsLeaf {
			hasDirectLeafChildren = true
			key := child.Idx.String()
			if colIdx, ok := g.LeafIndexMap[key]; ok {
				shares = append(shares, ShareInfo{
					GlobalCol: colIdx,
					X:         new(big.Int).Set(currentX),
				})
				currentX.Add(currentX, big.NewInt(1))
			}
		}
	}

	n := len(shares)
	t := node.T

	// 2. 如果直接子节点中有叶子，且 n > t，则生成 n-t 个线性约束
	if hasDirectLeafChildren && n > t {
		for k := t; k < n; k++ {
			// 临时使用 big.Rat 进行分数计算
			rowRat := make([]*big.Rat, g.TotalLeaves)
			for i := range rowRat {
				rowRat[i] = big.NewRat(0, 1)
			}

			targetShare := shares[k]
			rowRat[targetShare.GlobalCol] = big.NewRat(1, 1)

			// 计算拉格朗日插值系数
			for i := 0; i < t; i++ {
				baseShare := shares[i]
				numerator := big.NewRat(1, 1)
				denominator := big.NewRat(1, 1)

				for j := 0; j < t; j++ {
					if i == j {
						continue
					}
					xj := shares[j].X

					diffNum := new(big.Int).Sub(targetShare.X, xj)
					numerator.Mul(numerator, big.NewRat(0, 1).SetInt(diffNum))

					diffDen := new(big.Int).Sub(baseShare.X, xj)
					denominator.Mul(denominator, big.NewRat(0, 1).SetInt(diffDen))
				}

				Li := new(big.Rat).Quo(numerator, denominator)
				currentVal := rowRat[baseShare.GlobalCol]
				currentVal.Sub(currentVal, Li)
			}

			// 【关键步骤】将分数行转换为整数行
			// 1. 计算该行所有分母的最小公倍数 (LCM)
			lcm := big.NewInt(1)
			for _, val := range rowRat {
				if val.Sign() == 0 {
					continue
				}
				den := val.Denom()
				lcm = lcmOf(lcm, den)
			}

			// 2. 每个元素乘以 LCM 并取分子，得到整数
			rowInt := make([]*big.Int, g.TotalLeaves)
			for cIdx, val := range rowRat {
				temp := new(big.Rat).Mul(val, big.NewRat(0, 1).SetInt(lcm))
				rowInt[cIdx] = temp.Num()
			}

			// 3. 存入整数矩阵
			g.Rows = append(g.Rows, rowInt)
		}
	}

	// 3. 递归处理子节点 (直接调用自身)
	for _, child := range node.Children {
		Generate(g, child)
	}
}

// GetMatrix 直接返回生成的整数矩阵 [][]*big.Int
func GetMatrix(g *DualMatrixGenerator) [][]*big.Int {
	return g.Rows
}
