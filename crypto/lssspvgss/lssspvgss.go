package lssspvgss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/dleq"
	"pvgss/crypto/lssspvgss/lsss"
	"pvgss/crypto/node"
)

type Prf struct {
	Cp       []*bn128.G1
	Xc       *big.Int
	Shat     *big.Int
	Shatarry []*big.Int
}

func H(C, Cp []*bn128.G1) *big.Int {
	var combinedBytes []byte
	for _, point := range C {
		combinedBytes = append(combinedBytes, point.Marshal()...)
	}
	for _, point := range Cp {
		combinedBytes = append(combinedBytes, point.Marshal()...)
	}
	hash := sha256.Sum256(combinedBytes)
	hashBigInt := new(big.Int).SetBytes(hash[:])
	return hashBigInt
}

func PVGSSSetup() (*big.Int, *bn128.G1, *bn128.G2) {
	sk, _ := rand.Int(rand.Reader, bn128.Order)
	pk1 := new(bn128.G1).ScalarBaseMult(sk)
	pk2 := new(bn128.G2).ScalarBaseMult(sk)
	return sk, pk1, pk2
}

func PVGSSShare(s *big.Int, AA *node.Node, PK []*bn128.G1) ([]*bn128.G1, *Prf, error) {
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
	c := H(C, Cp)
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
	prfs := &Prf{
		Cp:       Cp,
		Xc:       c,
		Shat:     shat,
		Shatarry: shatarray,
	}
	return C, prfs, nil
}

// Invokes gssreconwithvrf to check
func PVGSSVerify(C []*bn128.G1, prfs *Prf, AA *node.Node, invmatrix1 [][]*big.Int, PK []*bn128.G1, I0, I1 []int) (bool, error) {
	for i := 0; i < len(C); i++ {
		left := prfs.Cp[i]
		temp1 := new(bn128.G1).ScalarMult(C[i], prfs.Xc)
		temp2 := new(bn128.G1).ScalarMult(PK[i], prfs.Shatarry[i])
		right := new(bn128.G1).Add(temp1, temp2)
		if left.String() != right.String() {
			return false, fmt.Errorf("check nizk proof fails")
		}
	}
	// Alice and Bob
	// I0 := make([]int, len(invmatrix0))
	// for i := 0; i < len(invmatrix0); i++ {
	// 	I0[0] = i
	// }
	recoverShat, err := lsss.Recon(AA, prfs.Shatarry, I0)
	if err != nil {
		return false, fmt.Errorf("GSSRecon fails")
	}
	if prfs.Shat.Cmp(recoverShat) != 0 {
		return false, fmt.Errorf("reconstruct shat dont match")
	}
	// Alice and Watchers
	// I1 := make([]int, len(invmatrix1))
	// I1[0] = 0
	// for i := 0; i < len(invmatrix1); i++ {
	// 	I1[i+1] = i + 2
	// }
	recoverShat, err = lsss.Recon(AA, prfs.Shatarry, I1)
	if err != nil {
		return false, fmt.Errorf("GSSRecon fails")
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

	// Generate DLEQ proof for decShare = C^skInv
	// 	We need to prove that log_C(decShare) = log_pk1(g1) where g1 = pk1^skInv
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1)) // generator of G1
	pk1 := new(bn128.G1).ScalarMult(g1, sk)           // pk1 = g1^sk

	// Calculate powers: (decShare, g1)
	powers := &dleq.Powers{
		G1: decShare, // decShare = C^skInv
		G2: g1,       // g1 = pk1^skInv (since pk1 = g1^sk, so g1 = pk1^skInv)
	}

	// Generate DLEQ proof using (C, pk1) as generators
	proof, err := dleq.DLEQProve(C, pk1, skInv, powers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate DLEQ proof: %v", err)
	}

	return decShare, proof, nil
}

func PVGSSKeyVrf(C, decShare *bn128.G1, pk1 *bn128.G1, proof *dleq.DLEQProof) (bool, error) {
	// Use DLEQ verification instead of pairing verification
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1)) // generator of G1

	// Calculate powers: (decShare, g1)
	// We need to verify that log_C(decShare) = log_pk1(g1)
	powers := &dleq.Powers{
		G1: decShare, // decShare = C^skInv
		G2: g1,       // g1 = pk1^skInv
	}

	// Verify DLEQ proof using (C, pk1) as generators
	if !dleq.DLEQVerify(C, pk1, powers, proof) {
		return false, fmt.Errorf("DLEQ verification failed")
	}

	return true, nil
}

func PVGSSRecon(AA *node.Node, Q []*bn128.G1, I []int) (*bn128.G1, error) {
	S, _ := lsss.GrpRecon(AA, Q, I)
	return S, nil
}
