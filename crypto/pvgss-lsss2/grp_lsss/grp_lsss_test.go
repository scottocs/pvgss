package grp_lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	// "pvgss/crypto/pvgsslsss/lsss"
	"pvgss/crypto/pvgss-sss/gss"
	"testing"
)

func TestGrpLSSS(t *testing.T) {
	// MSP =  (2 of (A, B, (2 of (P1, P2, P3))))
	AA := &gss.Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*gss.Node{
			{IsLeaf: true, Idx: big.NewInt(1)},
			{IsLeaf: true, Idx: big.NewInt(2)},
			{
				IsLeaf:      false,
				Childrennum: 3,
				T:           2,
				Idx:         big.NewInt(3),
				Children: []*gss.Node{
					{IsLeaf: true, Idx: big.NewInt(1)},
					{IsLeaf: true, Idx: big.NewInt(2)},
					{IsLeaf: true, Idx: big.NewInt(3)},
				},
			},
		},
	}

	secret, _ := rand.Int(rand.Reader, bn128.Order)
	S := new(bn128.G1).ScalarBaseMult(secret)
	shares, _ := GrpLSSSShare(S, AA)
	I := make([]int, 3)
	I[0] = 0
	I[1] = 2
	I[2] = 4
	recoverShares := make([]*bn128.G1, 3)
	recoverShares[0] = shares[0]
	recoverShares[1] = shares[2]
	recoverShares[2] = shares[4]
	reconS, _ := GrpLSSSRecon(AA, recoverShares, I)
	fmt.Println("original secret = ", S)
	fmt.Println("recover secret  = ", reconS)
	if reconS.String() == S.String() {
		fmt.Print("Secret reconstruction successful!\n")
	}
}
