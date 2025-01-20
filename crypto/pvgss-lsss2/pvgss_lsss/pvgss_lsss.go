package pvgss_lsss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-lsss2/grp_lsss"
	"pvgss/crypto/pvgss-lsss2/lsss"
	"pvgss/crypto/pvgss-sss/gss"
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

func PVGSSShare(s *big.Int, AA *gss.Node, PK []*bn128.G1) ([]*bn128.G1, *Prf, error) {
	C := make([]*bn128.G1, len(PK))
	Cp := make([]*bn128.G1, len(PK))
	shares, _ := lsss.LSSSShare(s, AA)
	for i := 0; i < len(PK); i++ {
		C[i] = new(bn128.G1).ScalarMult(PK[i], shares[i])
	}
	sp, _ := rand.Int(rand.Reader, bn128.Order)
	sharesp, _ := lsss.LSSSShare(sp, AA)
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

func PVGSSVerify(C []*bn128.G1, prfs *Prf, AA *gss.Node, PK []*bn128.G1, I []int) (bool, error) {
	for i := 0; i < len(C); i++ {
		left := prfs.Cp[i]
		temp1 := new(bn128.G1).ScalarMult(C[i], prfs.Xc)
		temp2 := new(bn128.G1).ScalarMult(PK[i], prfs.Shatarry[i])
		right := new(bn128.G1).Add(temp1, temp2)
		if left.String() != right.String() {
			return false, fmt.Errorf("check nizk proof fails")
		}
		recoverShat, err := lsss.LSSSRecon(AA, prfs.Shatarry, I)
		if err != nil {
			return false, fmt.Errorf("GSSRecon fails")
		}
		if prfs.Shat.Cmp(recoverShat) != 0 {
			return false, fmt.Errorf("reconstruct shat dont match")
		}
	}
	return true, nil
}

func PVGSSPreRecon(C *bn128.G1, sk *big.Int) (*bn128.G1, error) {
	skInv := new(big.Int).ModInverse(sk, bn128.Order)
	if skInv == nil {
		return nil, fmt.Errorf("no inverse for sk")
	}
	if new(big.Int).Mod(new(big.Int).Mul(sk, skInv), bn128.Order).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("inverse for sk is wrong")
	}
	if skInv.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("inverse for sk is neg")
	}
	decShare := new(bn128.G1).ScalarMult(C, skInv)
	return decShare, nil
}

func PVGSSKeyVrf(C, decShare *bn128.G1, pk2 *bn128.G2) (bool, error) {
	gen2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	left := bn128.Pair(decShare, pk2)
	right := bn128.Pair(C, gen2)
	if left.String() != right.String() {
		fmt.Println("left:", left.String())
		fmt.Println("right:", right.String())
		return false, fmt.Errorf("check decryption fails")
	}
	return true, nil
}

func PVGSSRecon(AA *gss.Node, Q []*bn128.G1, I []int) (*bn128.G1, error) {
	S, _ := grp_lsss.GrpLSSSRecon(AA, Q, I)
	return S, nil
}
