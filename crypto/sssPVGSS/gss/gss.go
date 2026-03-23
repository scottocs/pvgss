// Generalized Secret Sharing on Shamir SS
package gss

import (
	"errors"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
	"pvgss/crypto/ssspvgss/sss"
)

func GSSShare(secret *big.Int, AA *node.Node) ([]*big.Int, error) {
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

// The AA here is different from the AA in GSSShare,
// the AA here is a subset of the above AA and is a path path that satisfies the access control structure
func GSSRecon(AA *node.Node, Q []*big.Int) (*big.Int, *big.Int, error) {
	if AA == nil {
		return nil, nil, errors.New("AA is empty")
	}
	// Init offset as 0
	secret, _, err := reconRecursive(AA, Q, 0)
	if err != nil {
		return nil, nil, err
	}
	return secret, AA.Idx, nil
}

func reconRecursive(AA *node.Node, Q []*big.Int, offset int) (*big.Int, int, error) {
	if AA.IsLeaf {
		if offset >= len(Q) {
			return nil, 0, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d out of range)", AA.Idx, offset)
		}
		s := Q[offset]
		// Leaf nodes consume 1 shard
		return s, 1, nil
	}
	childShares := make([]*big.Int, 0, AA.Childrennum)
	childIdx := make([]*big.Int, 0, AA.Childrennum)
	// Non-leaf nodes consume the number of shards
	currentOffset := offset
	for i := 0; i < AA.Childrennum; i++ {
		if i >= len(AA.Children) || AA.Children[i] == nil {
			return nil, 0, fmt.Errorf("node [ID:%v]: missing child at index %d", AA.Idx, i)
		}
		child := AA.Children[i]
		share, consumed, err := reconRecursive(child, Q, currentOffset)
		if err != nil {
			return nil, 0, err
		}
		childShares = append(childShares, share)
		childIdx = append(childIdx, child.Idx)
		currentOffset += consumed
	}
	if len(childShares) < AA.T {
		return nil, 0, fmt.Errorf("node [ID:%v]: insufficient child secrets (%d < %d)", AA.Idx, len(childShares), AA.T)
	}
	// 4. Recover the secret using the first t shares
	recovered, err := sss.Recon(childShares[:AA.T], childIdx[:AA.T], AA.T)
	if err != nil {
		return nil, 0, err
	}
	// 5. Return the current secret and total consumed shards
	totalConsumed := currentOffset - offset
	return recovered, totalConsumed, nil
}

func GrpGSSShare(Secret *bn128.G1, AA *node.Node) ([]*bn128.G1, error) {
	var S []*bn128.G1
	if AA.IsLeaf {
		// If it is a leaf node, the secret is added to the result
		S = append(S, Secret)
		return S, nil
	} else {
		// If it is a non-leaf node, distribute the secret to the child nodes
		shares, err := sss.GrpShare(Secret, AA.Childrennum, AA.T)
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

func GrpGSSRecon(AA *node.Node, Q []*bn128.G1) (*bn128.G1, *big.Int, error) {
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

	recovered, err := sss.GrpRecon(childShares[:AA.T], childIdx[:AA.T]) // 传入下标数组
	if err != nil {
		return nil, nil, err
	}
	return recovered, AA.Idx, nil
}

func GetLen(node *node.Node) int {
	if node.IsLeaf {
		return 1
	} else {
		length := 0
		for _, child := range node.Children {
			length += GetLen(child)
		}
		return length
	}
}
