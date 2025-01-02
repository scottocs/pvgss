// Implementation of PVGSS based on GSS from LSSS.
package pvgss_lsss

import (
	"fmt"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"math/big"
)

type GSS struct {
	P *big.Int
}
type GSSShare struct {
	// represent shareholder
	ID string
	// share value
	value *big.Int
}

type GrpGSS struct {
	P  *big.Int
	G1 *bn128.G1
	G2 *bn128.G2
	Gt *bn128.GT
}
type GrpGSSShare struct {
	// represent shareholder
	ID string
	// share value
	value *bn128.G1
}

type PVGSS struct {
	P  *big.Int
	G1 *bn128.G1
	G2 *bn128.G2
	Gt *bn128.GT
}

// NewGSS configures a new instance of the scheme.
func NewGSS() *GSS {
	return &GSS{
		P: bn128.Order,
	}
}

// NewGSS configures a new instance of the scheme.
func NewGrpGSS() *GrpGSS {
	gen1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	gen2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	return &GrpGSS{
		P:  bn128.Order,
		G1: gen1,
		G2: gen2,
		Gt: bn128.Pair(gen1, gen2),
	}
}

func (a *GSS) LSSShare(s *big.Int, msp *lib.MSP) ([]*GSSShare, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	holders := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if holders[i] {
			return nil, fmt.Errorf("some holders correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		holders[i] = true
	}

	//using LSSS share

	// rand generator
	sampler := sample.NewUniform(a.P)
	// pick random vector v
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	// set first element as secret s
	v[0] = s

	//get shares which belongs to shareholders \rho(i)
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}

	shares := make([]*GSSShare, len(lambdaI))

	// Iterate through lambdaI and msp.RowToAttrib to create GSSShare
	for i := 0; i < len(lambdaI); i++ {
		shares[i] = &GSSShare{
			ID:    msp.RowToAttrib[i], // Set the attribute name as ID
			value: lambdaI[i],         // Set the corresponding share
		}
	}
	return shares, nil
}

func (a *GSS) LSSSRecon(msp *lib.MSP, shares []*GSSShare) (*big.Int, error) {
	goodMatRows := make([]data.Vector, 0)
	goodHolders := make([]string, 0)
	idToShare := make(map[string]*big.Int)
	for _, share := range shares {
		idToShare[share.ID] = share.value
	}
	for i, id := range msp.RowToAttrib {
		if idToShare[id] != nil {
			goodMatRows = append(goodMatRows, msp.Mat[i])
			goodHolders = append(goodHolders, id)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return nil, err
	}

	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, holders are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return nil, fmt.Errorf("no good matrix columns")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
	if err != nil {
		return nil, err
	}
	s := big.NewInt(0)
	for i, id := range goodHolders {
		s.Add(s, new(big.Int).Mul(c[i], idToShare[id]))
	}
	s.Mod(s, a.P)
	return s, nil
}

func (a *GrpGSS) GrpLSSSShare(S *bn128.G1, msp *lib.MSP) ([]*GrpGSSShare, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	holders := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if holders[i] {
			return nil, fmt.Errorf("some holders correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		holders[i] = true
	}

	//using LSSS share

	// rand generator
	sampler := sample.NewUniform(a.P)
	// pick random vector v
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	// set first element as 1
	v[0] = big.NewInt(1)

	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}

	shares := make([]*GrpGSSShare, len(lambdaI))

	//create GrpGSSShare
	for i := 0; i < len(lambdaI); i++ {
		signLambda := lambdaI[i].Cmp(big.NewInt(0))
		if signLambda >= 0 {
			shares[i] = &GrpGSSShare{
				ID:    msp.RowToAttrib[i],                      // Set the attribute name as ID
				value: new(bn128.G1).ScalarMult(S, lambdaI[i]), // Set the corresponding share
			}
		} else {
			shares[i] = &GrpGSSShare{
				ID:    msp.RowToAttrib[i],
				value: new(bn128.G1).ScalarMult(new(bn128.G1).Neg(S), new(big.Int).Abs(lambdaI[i])),
			}
		}

	}
	return shares, nil
}

func (a *GrpGSS) GrpLSSSRecon(msp *lib.MSP, shares []*GrpGSSShare) (*bn128.G1, error) {
	goodMatRows := make([]data.Vector, 0)
	goodHolders := make([]string, 0)
	idToShare := make(map[string]*bn128.G1)
	for _, share := range shares {
		idToShare[share.ID] = share.value
	}
	for i, id := range msp.RowToAttrib {
		if idToShare[id] != nil {
			goodMatRows = append(goodMatRows, msp.Mat[i])
			goodHolders = append(goodHolders, id)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return nil, err
	}

	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, holders are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return nil, fmt.Errorf("no good matrix columns")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
	if err != nil {
		return nil, err
	}

	s := new(bn128.G1).ScalarBaseMult(big.NewInt(0))

	for i, id := range goodHolders {
		if c[i].Cmp(big.NewInt(0)) >= 0 {
			s.Add(s, new(bn128.G1).ScalarMult(idToShare[id], c[i]))
		} else {
			s.Add(s, new(bn128.G1).ScalarMult(new(bn128.G1).Neg(idToShare[id]), new(big.Int).Abs(c[i])))
		}
	}
	return s, nil
}
