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
		// 如果是叶子节点，将秘密加入结果
		S = append(S, Secret)
		return S, nil
	} else {
		// 如果是非叶子节点，分发秘密给孩子节点
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
	// 如果是叶子节点，从Q中获取秘密
	if AA.IsLeaf {
		if len(Q) == 0 {
			return nil, nil, errors.New("insufficient shares for leaf node")
		}
		s := Q[0]
		return s, AA.Idx, nil
	}
	// 非叶子节点，递归处理每个子节点
	childShares := make([]*bn128.G1, 0, AA.Childrennum)
	childIdx := make([]*big.Int, 0, AA.Childrennum)
	for i, child := range AA.Children[:AA.T] {
		// 递归恢复子节点的秘密
		share, idx, err := GrpGSSRecon(child, Q[i:])
		if err != nil {
			return nil, nil, err
		}
		// 收集子节点的秘密
		childShares = append(childShares, share)
		childIdx = append(childIdx, idx)
	}
	// 如果子节点的共享值不足以恢复出当前秘密
	if len(childShares) < AA.T {
		return nil, nil, errors.New("insufficient shares for non-leaf node")
	}
	// 使用Shamir重构当前节点的秘密
	recovered, err := grp_sss.GrpRecon(childShares[:AA.T], childIdx[:AA.T]) // 传入下标数组
	if err != nil {
		return nil, nil, err
	}
	return recovered, AA.Idx, nil
}
