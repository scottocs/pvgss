// Generalized Secret Sharing on Shamir SS
package gss

import (
	"errors"
	"math/big"
	"pvgss/crypto/pvgss-sss/sss"
)

type Node struct {
	IsLeaf      bool
	Children    []*Node
	Childrennum int
	T           int
	Idx         *big.Int
}

func GSSShare(secret *big.Int, AA *Node) ([]*big.Int, error) {
	var s []*big.Int
	if AA.IsLeaf {
		s = append(s, secret)
		return s, nil
	} else {
		shares, err := sss.Share(secret, AA.Childrennum, AA.T)
		if err != nil {
			return nil, err
		}
		for i, child := range AA.Children {
			childShares, err := GSSShare(shares[i], child)
			if err != nil {
				return nil, err
			}

			s = append(s, childShares...)
		}
	}
	return s, nil
}

// 此处的AA与GSSShare中的AA不同，此处的AA 是上面 AA 的子集,是一个满足访问控制结构的路径 path
func GSSRecon(AA *Node, Q []*big.Int) (*big.Int, *big.Int, error) {
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
	childShares := make([]*big.Int, 0, AA.Childrennum)
	childIdx := make([]*big.Int, 0, AA.Childrennum)
	// childI := make([]*big.Int, AA.Childrennum)
	for i, child := range AA.Children[:AA.T] {
		// 递归恢复子节点的秘密
		// childIdx = append(childIdx, child.Idx)
		share, idx, err := GSSRecon(child, Q[i:])
		if err != nil {
			return nil, nil, err
		}
		// 收集子节点的秘密
		childShares = append(childShares, share)
		childIdx = append(childIdx, idx)
		// child
	}
	// 如果子节点的共享值不足以恢复出当前秘密
	if len(childShares) < AA.T {
		return nil, nil, errors.New("insufficient shares for non-leaf node")
	}
	// 使用Shamir重构当前节点的秘密
	// fmt.Println("idx = ", childIdx)
	recovered, err := sss.Recon(childShares[:AA.T], childIdx[:AA.T]) // 传入下标数组
	if err != nil {
		return nil, nil, err
	}
	return recovered, AA.Idx, nil
}

func NewNode(IsLeaf bool, num int, T int, idx *big.Int) *Node {
	return &Node{
		IsLeaf:      IsLeaf,
		Children:    []*Node{},
		Childrennum: num,
		T:           T,
		Idx:         idx,
	}
}

func GetLen(node *Node) int {
	if node.IsLeaf {
		// 是叶子节点
		return 1
	} else {
		// 若是非叶子节点，递归计算所有子结点总长度
		length := 0
		for _, child := range node.Children {
			length += GetLen(child)
		}
		return length
	}
}
