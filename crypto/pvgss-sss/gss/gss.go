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

// The AA here is different from the AA in GSSShare,
// the AA here is a subset of the above AA and is a path path that satisfies the access control structure
func GSSRecon(AA *Node, Q []*big.Int) (*big.Int, *big.Int, error) {
	if AA == nil {
		return nil, nil, errors.New("AA is empty")
	}
	// If it is a leaf node, take the secret from Q
	if AA.IsLeaf {
		if len(Q) == 0 {
			return nil, nil, errors.New("insufficient shares for leaf node")
		}
		s := Q[0]
		return s, AA.Idx, nil
	}
	// Non-leaf nodes, recursively process each child node
	childShares := make([]*big.Int, 0, AA.Childrennum)
	childIdx := make([]*big.Int, 0, AA.Childrennum)
	// childI := make([]*big.Int, AA.Childrennum)
	for i, child := range AA.Children[:AA.T] {
		// childIdx = append(childIdx, child.Idx)
		share, idx, err := GSSRecon(child, Q[i:])
		if err != nil {
			return nil, nil, err
		}
		// Collect the secrets of the child nodes
		childShares = append(childShares, share)
		childIdx = append(childIdx, idx)
		// child
	}

	if len(childShares) < AA.T {
		return nil, nil, errors.New("insufficient shares for non-leaf node")
	}

	recovered, err := sss.Recon(childShares[:AA.T], childIdx[:AA.T])
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
		return 1
	} else {
		length := 0
		for _, child := range node.Children {
			length += GetLen(child)
		}
		return length
	}
}
