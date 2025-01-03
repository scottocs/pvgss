// Implementation of PVGSS based on GSS from LSSS.
package pvgss_lsss

import (
	"crypto/sha256"
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
}
type GrpGSSShare struct {
	// represent shareholder
	ID string
	// share value
	value *bn128.G1
}

type PvGSS struct {
	P  *big.Int
	G1 *bn128.G1
	G2 *bn128.G2
	Gt *bn128.GT
}

// NIZK proof of sharing
type proof struct {
	commit *bn128.G1
	chal   *big.Int
	resp   *big.Int
}

type PvGSSShare struct {
	// represent shareholder
	ID string

	// share value
	value *bn128.G1

	// NIZK proof
	proof proof
}

// NewGSS configures a new instance of the scheme.
func NewGSS(order *big.Int) *GSS {
	return &GSS{
		P: order,
	}
}

// NewGSS configures a new instance of the scheme.
func NewGrpGSS(order *big.Int, gen1 *bn128.G1) *GrpGSS {
	return &GrpGSS{
		P:  order,
		G1: gen1,
	}
}

func NewPvGSS() *PvGSS {
	gen1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	gen2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	return &PvGSS{
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
	//for debug
	//for i, ci := range c {
	//	fmt.Println("gssrecon c", i, "=", ci)
	//}
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

func (a *PvGSS) Setup(holders []string) (map[string]*big.Int, map[string]*bn128.G1, map[string]*bn128.G2, error) {
	n := len(holders)
	if n <= 0 {
		return nil, nil, nil, fmt.Errorf("number of shareholders must be greater than 0")
	}

	// Lists to store the generated private keys and public keys
	skMap := make(map[string]*big.Int)
	pk1Map := make(map[string]*bn128.G1)
	pk2Map := make(map[string]*bn128.G2)

	// Generate key pairs for each shareholder
	for i := 0; i < n; i++ {
		holder := holders[i]
		// Generate a random private key sk
		sampler := sample.NewUniform(a.P)
		sk, err := sampler.Sample()

		if err != nil {
			return nil, nil, nil, err
		}
		// Compute the corresponding public key pk1 = g1^sk, pk2 = g2^sk
		pk1 := new(bn128.G1).ScalarMult(a.G1, sk)
		pk2 := new(bn128.G2).ScalarMult(a.G2, sk)

		// Store the keys in the maps with the holder's name as the key
		skMap[holder] = sk
		pk1Map[holder] = pk1
		pk2Map[holder] = pk2

		//check match of pk1 and pk2  e(pk1,g2) == e(g1, pk2)
		left := bn128.Pair(pk1, a.G2)
		right := bn128.Pair(a.G1, pk2)
		if left.String() != right.String() {
			return nil, nil, nil, fmt.Errorf("check pk1 and pk2 match fails")
		}
	}

	return skMap, pk1Map, pk2Map, nil
}

func (a *PvGSS) Share(s *big.Int, msp *lib.MSP, pkMap map[string]*bn128.G1) ([]*PvGSSShare, *big.Int, error) {
	n := len(msp.RowToAttrib)
	if n != len(pkMap) {
		return nil, nil, fmt.Errorf("number of public keys must match the number of shareholders")
	}

	// Step 1: Secret sharing using GSS based on LSSS
	gss := NewGSS(a.P)
	shares, err := gss.LSSShare(s, msp)
	if err != nil {
		return nil, nil, fmt.Errorf("error in GSSShare: %w", err)
	}

	// Step 2: shares C_i = pk_i^s_i
	Ci := make([]*bn128.G1, n)
	for i, share := range shares {
		if share.value.Cmp(big.NewInt(0)) >= 0 {
			Ci[i] = new(bn128.G1).ScalarMult(pkMap[share.ID], share.value)
		} else {
			Ci[i] = new(bn128.G1).ScalarMult(new(bn128.G1).Neg(pkMap[share.ID]), new(big.Int).Abs(share.value))
		}
	}

	// Step 3: Generate a random scalar s'
	sampler := sample.NewUniform(a.P)
	sPrime, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}

	// Step 4: Secret sharing for s' using GSS
	sharesPrime, err := gss.LSSShare(sPrime, msp)
	if err != nil {
		return nil, nil, fmt.Errorf("error in GSSShare for s': %w", err)
	}

	// Step 5: Commitments C'_i = pk_i^s'_i
	CiPrime := make([]*bn128.G1, n)
	for i, sharePrime := range sharesPrime {
		if sharePrime.value.Cmp(big.NewInt(0)) >= 0 {
			CiPrime[i] = new(bn128.G1).ScalarMult(pkMap[sharePrime.ID], sharePrime.value)
		} else {
			CiPrime[i] = new(bn128.G1).ScalarMult(new(bn128.G1).Neg(pkMap[sharePrime.ID]), new(big.Int).Abs(sharePrime.value))
		}
	}

	// Step 6: Compute Fiat-Shamir challenge c = H({C_i} || {C'_i})
	preImage := ""
	for i, ci := range Ci {
		preImage += ci.String() + CiPrime[i].String()
	}
	h := sha256.Sum256([]byte(preImage))
	hashNum := new(big.Int).SetBytes(h[:])
	chal := new(big.Int).Mod(hashNum, a.P)

	sHat := new(big.Int).Mod(new(big.Int).Sub(sPrime, new(big.Int).Mul(chal, s)), a.P)
	//another method to get chal
	//for {
	//	hashNum.SetBytes(h[:])
	//	if hashNum.Cmp(a.P) == -1 {
	//		break
	//	}
	//	h = sha256.Sum256(h[:])
	//}

	// Step 7: Compute responses resp_i = s'_i - c * s_i for each i
	resp := make([]*big.Int, n)
	for i := range shares {
		resp[i] = new(big.Int).Sub(sharesPrime[i].value, new(big.Int).Mul(chal, shares[i].value))
		resp[i].Mod(resp[i], a.P)
	}

	// Step 8: Generate PvGSSShare outputs with NIZK proof
	pvShares := make([]*PvGSSShare, n)
	for i, share := range shares {
		pvShares[i] = &PvGSSShare{
			ID:    share.ID,
			value: Ci[i], // share value
			proof: proof{
				commit: CiPrime[i], // Commitment C'_i
				chal:   chal,       // Fiat-Shamir challenge
				resp:   resp[i],    // Response
			},
		}
	}
	return pvShares, sHat, nil
}

func (a *PvGSS) Verify(shares []*PvGSSShare, msp *lib.MSP, sHat *big.Int, pkMap map[string]*bn128.G1) (bool, error) {
	if len(shares) != msp.Mat.Rows() {
		return false, fmt.Errorf("number of shares should match rows of access structure")
	}
	gssShares := make([]*GSSShare, len(shares))
	for i, share := range shares {
		c := share.value
		cPrime := share.proof.commit
		chal := share.proof.chal
		resp := share.proof.resp

		right := new(bn128.G1).Add(new(bn128.G1).ScalarMult(c, chal), new(bn128.G1).ScalarMult(pkMap[share.ID], resp))

		//check equal of cPrime and right
		if cPrime.String() != right.String() {
			return false, fmt.Errorf("check nizk proof fails")
		}
		gssShares[i] = &GSSShare{
			ID:    share.ID,
			value: resp,
		}
	}

	gss := NewGSS(a.P)
	recon, err := gss.LSSSRecon(msp, gssShares)
	if err != nil {
		return false, fmt.Errorf("reconstruct by NIZK response value failed")
	} else {
		if recon.Cmp(sHat) != 0 {
			return false, fmt.Errorf("reconstruct s hat don't match")
		}
	}
	return true, nil
}

func (a *PvGSS) PreRecon(share *PvGSSShare, sk *big.Int) (*bn128.G1, error) {
	skInv := new(big.Int).ModInverse(sk, a.P)
	if skInv == nil {
		return nil, fmt.Errorf("no inverse for sk")
	}
	if new(big.Int).Mod(new(big.Int).Mul(sk, skInv), a.P).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("inverse for sk is wrong")
	}

	if skInv.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("inverse for sk is neg")
	}

	decShare := new(bn128.G1).ScalarMult(share.value, skInv)
	return decShare, nil
}
func (a *PvGSS) KeyVrf(share *PvGSSShare, decShare *bn128.G1, pk2 *bn128.G2) (bool, error) {
	left := bn128.Pair(decShare, pk2)
	right := bn128.Pair(share.value, a.G2)
	if left.String() != right.String() {
		fmt.Println("left:", left.String())
		fmt.Println("right:", right.String())
		return false, fmt.Errorf("check decryption fails")
	}
	return true, nil
}
func (a *PvGSS) Recon(msp *lib.MSP, shares []*GrpGSSShare) (*bn128.G1, error) {
	grpGss := NewGrpGSS(a.P, a.G1)
	return grpGss.GrpLSSSRecon(msp, shares)
}
