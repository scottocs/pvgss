package lssspvgss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/dleq"
	"pvgss/crypto/gsstesting"
	"pvgss/crypto/lssspvgss/lsss"
	"pvgss/crypto/node"
	"pvgss/crypto/transcript"
)

type Proof struct {
	Cp       []*bn128.G1
	Xc       *big.Int
	Shat     *big.Int
	Shatarry []*big.Int
}

func PVGSSSetup() (*big.Int, *bn128.G1) {
	sk, _ := rand.Int(rand.Reader, bn128.Order)
	for sk.Sign() == 0 {
		sk, _ = rand.Int(rand.Reader, bn128.Order)
	}
	pk1 := new(bn128.G1).ScalarBaseMult(sk)
	return sk, pk1
}

func PVGSSShare(s *big.Int, AA *node.Node, PK []*bn128.G1) ([]*bn128.G1, *Proof, error) {
	C := make([]*bn128.G1, len(PK))
	Cp := make([]*bn128.G1, len(PK))
	shares, _ := lsss.Share(s, AA)
	for i := 0; i < len(PK); i++ {
		C[i] = new(bn128.G1).ScalarMult(PK[i], shares[i])
	}
	sp, _ := rand.Int(rand.Reader, bn128.Order)
	sharesp, _ := lsss.Share(sp, AA)
	for i := 0; i < len(PK); i++ {
		Cp[i] = new(bn128.G1).ScalarMult(PK[i], sharesp[i])
	}
	c := transcript.SharingChallenge(AA, PK, C, Cp)
	temp := new(big.Int).Mul(c, s)
	temp.Mod(temp, bn128.Order)
	shat := new(big.Int).Sub(sp, temp)
	shat.Mod(shat, bn128.Order)
	shatarray := make([]*big.Int, len(PK))
	for i := 0; i < len(PK); i++ {
		temp := new(big.Int).Mul(c, shares[i])
		temp.Mod(temp, bn128.Order)
		shatarray[i] = new(big.Int).Sub(sharesp[i], temp)
		shatarray[i].Mod(shatarray[i], bn128.Order)
	}
	prfs := &Proof{
		Cp:       Cp,
		Xc:       c,
		Shat:     shat,
		Shatarry: shatarray,
	}
	return C, prfs, nil
}

func PVGSSVerify(C []*bn128.G1, prfs *Proof, root *node.Node, PK []*bn128.G1) (bool, error) {
	return verifyWithGSSTest(C, prfs, root, PK, gsstesting.GSSTest)
}

func PVGSSVerifyExact(C []*bn128.G1, prfs *Proof, root *node.Node, PK []*bn128.G1) (bool, error) {
	return verifyWithGSSTest(C, prfs, root, PK, gsstesting.GSSTestExact)
}

func PVGSSVerifyDual(C []*bn128.G1, prfs *Proof, root *node.Node, PK []*bn128.G1) (bool, error) {
	dualTest := func(root *node.Node, shares []*big.Int) (*big.Int, bool, error) {
		seed := transcript.DualTestSeed(root, shares, PK, C, prfs.Cp)
		return gsstesting.GSSTestDualWithSeed(root, shares, seed)
	}
	return verifyWithGSSTest(C, prfs, root, PK, dualTest)
}

func verifyWithGSSTest(C []*bn128.G1, prfs *Proof, root *node.Node, PK []*bn128.G1, gssTest func(*node.Node, []*big.Int) (*big.Int, bool, error)) (bool, error) {
	if prfs == nil || root == nil || len(C) == 0 || len(C) != len(PK) ||
		len(C) != len(prfs.Cp) || len(C) != len(prfs.Shatarry) {
		return false, fmt.Errorf("invalid PVGSS transcript dimensions")
	}
	expectedChallenge := transcript.SharingChallenge(root, PK, C, prfs.Cp)
	if prfs.Xc == nil || prfs.Xc.Cmp(expectedChallenge) != 0 {
		return false, fmt.Errorf("Fiat-Shamir challenge mismatch")
	}
	for i := 0; i < len(C); i++ {
		left := prfs.Cp[i]
		temp1 := new(bn128.G1).ScalarMult(C[i], prfs.Xc)
		temp2 := new(bn128.G1).ScalarMult(PK[i], prfs.Shatarry[i])
		right := new(bn128.G1).Add(temp1, temp2)
		if left.String() != right.String() {
			return false, fmt.Errorf("check nizk proof fails")
		}
	}
	recoverShat, valid, err := gssTest(root, prfs.Shatarry)
	if err != nil {
		return false, fmt.Errorf("GSS testing fails: %w", err)
	}
	if !valid {
		return false, fmt.Errorf("GSS testing rejects the proof responses")
	}
	if prfs.Shat.Cmp(recoverShat) != 0 {
		return false, fmt.Errorf("reconstruct shat dont match")
	}
	return true, nil
}

func PVGSSPreRecon(C *bn128.G1, sk *big.Int) (*bn128.G1, *dleq.DLEQProof, error) {
	skInv := new(big.Int).ModInverse(sk, bn128.Order)
	if skInv == nil {
		return nil, nil, fmt.Errorf("no inverse for sk")
	}
	if new(big.Int).Mod(new(big.Int).Mul(sk, skInv), bn128.Order).Cmp(big.NewInt(1)) != 0 {
		return nil, nil, fmt.Errorf("inverse for sk is wrong")
	}
	if skInv.Cmp(big.NewInt(0)) == -1 {
		return nil, nil, fmt.Errorf("inverse for sk is neg")
	}
	decShare := new(bn128.G1).ScalarMult(C, skInv)

	// Prove log_g(pk1) = log_decShare(C) = sk.
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	pk1 := new(bn128.G1).ScalarMult(g1, sk)
	powers := &dleq.Powers{
		G1: pk1,
		G2: C,
	}
	proof, err := dleq.DLEQProve(g1, decShare, sk, powers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate DLEQ proof: %v", err)
	}

	return decShare, proof, nil
}

func PVGSSKeyVrf(C, decShare *bn128.G1, pk1 *bn128.G1, proof *dleq.DLEQProof) (bool, error) {
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	powers := &dleq.Powers{
		G1: pk1,
		G2: C,
	}
	if !dleq.DLEQVerify(g1, decShare, powers, proof) {
		return false, fmt.Errorf("DLEQ verification failed")
	}

	return true, nil
}

func PVGSSRecon(AA *node.Node, Q []*bn128.G1, I []int) (*bn128.G1, error) {
	return lsss.GrpRecon(AA, Q, I)
}

func PrepareReconWeights(AA *node.Node, I []int) ([]*big.Int, error) {
	matrix := lsss.Convert(AA)
	return lsss.ReconstructionWeightsForRows(matrix, I)
}

func PVGSSReconWithWeights(Q []*bn128.G1, I []int, weights []*big.Int) (*bn128.G1, error) {
	return lsss.GrpReconWithWeights(Q, I, weights)
}
