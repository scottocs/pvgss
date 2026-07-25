package transcript

import (
	"crypto/sha256"
	"hash"
	"math/big"

	bn128 "pvgss/bn128"
	"pvgss/crypto/node"
)

const sharingDomain = "PVGSS-SHARE-v1"
const dualTestDomain = "PVGSS-DUAL-v1"

// SharingChallenge hashes the complete public statement in a canonical order.
func SharingChallenge(root *node.Node, publicKeys, ciphertexts, commitments []*bn128.G1) *big.Int {
	h := sha256.New()
	_, _ = h.Write([]byte(sharingDomain))
	writeNode(h, root)
	writePoints(h, publicKeys)
	writePoints(h, ciphertexts)
	writePoints(h, commitments)
	out := new(big.Int).SetBytes(h.Sum(nil))
	return out.Mod(out, bn128.Order)
}

// DualTestSeed deterministically samples the dual-code check in the random-oracle model.
func DualTestSeed(root *node.Node, shares []*big.Int, publicKeys, ciphertexts, commitments []*bn128.G1) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(dualTestDomain))
	writeNode(h, root)
	for _, share := range shares {
		writeUint256(h, share)
	}
	writePoints(h, publicKeys)
	writePoints(h, ciphertexts)
	writePoints(h, commitments)
	return h.Sum(nil)
}

func writeNode(h hash.Hash, n *node.Node) {
	if n.IsLeaf {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	writeUint256(h, big.NewInt(int64(n.ChildrenNum)))
	writeUint256(h, big.NewInt(int64(n.T)))
	for _, child := range n.Children {
		writeNode(h, child)
	}
}

func writePoints(h hash.Hash, points []*bn128.G1) {
	for _, point := range points {
		_, _ = h.Write(point.Marshal())
	}
}

func writeUint256(h hash.Hash, value *big.Int) {
	var encoded [32]byte
	if value != nil {
		bytes := value.Bytes()
		if len(bytes) > len(encoded) {
			bytes = bytes[len(bytes)-len(encoded):]
		}
		copy(encoded[len(encoded)-len(bytes):], bytes)
	}
	_, _ = h.Write(encoded[:])
}
