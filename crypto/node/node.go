package node

import "math/big"

type Node struct {
	IsLeaf      bool
	Children    []*Node
	Childrennum int
	T           int
	Idx         *big.Int
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
