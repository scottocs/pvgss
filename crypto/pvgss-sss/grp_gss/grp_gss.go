// GSS scheme on Group G based on Shamir secret sharing
package grpgss

import (
	// "errors"
	"errors"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/pvgss-sss/grp_sss"
	"pvgss/crypto/pvgss-sss/gss"
)

// A，B and {Pi} 's PK

func GrpGSSShare(Secret *bn128.G1, AA *gss.Node) ([]*bn128.G1, error) {
	var S []*bn128.G1
	if AA.IsLeaf {
		// If it is a leaf node, the secret is added to the result
		S = append(S, Secret)
		return S, nil
	} else {
		// If it is a non-leaf node, distribute the secret to the child nodes
		shares, err := grp_sss.GrpShare(Secret, AA.Childrennum, AA.T)
		if err != nil {
			return nil, err
		}
		for i, child := range AA.Children {
			childShares, err := GrpGSSShare(shares[i], child)
			if err != nil {
				return nil, err
			}

			S = append(S, childShares...)
		}
	}
	return S, nil
}

func GrpGSSRecon(AA *gss.Node, Q []*bn128.G1) (*bn128.G1, *big.Int, error) {
	if AA == nil {
		return nil, nil, errors.New("AA is empty")
	}

	if AA.IsLeaf {
		if len(Q) == 0 {
			return nil, nil, errors.New("insufficient shares for leaf node")
		}
		s := Q[0]
		return s, AA.Idx, nil
	}

	childShares := make([]*bn128.G1, 0, AA.Childrennum)
	childIdx := make([]*big.Int, 0, AA.Childrennum)
	for i, child := range AA.Children[:AA.T] {
		share, idx, err := GrpGSSRecon(child, Q[i:])
		if err != nil {
			return nil, nil, err
		}
		childShares = append(childShares, share)
		childIdx = append(childIdx, idx)
	}

	if len(childShares) < AA.T {
		return nil, nil, errors.New("insufficient shares for non-leaf node")
	}

	recovered, err := grp_sss.GrpRecon(childShares[:AA.T], childIdx[:AA.T]) // 传入下标数组
	if err != nil {
		return nil, nil, err
	}
	return recovered, AA.Idx, nil
}
