package pvgss_lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	bn128 "pvgss/bn128"

	// "pvgss/crypto/pvgsslsss/lsss"
	"testing"

	"pvgss/crypto/pvgss-sss/gss"

	"github.com/stretchr/testify/assert"
)

func TestPVGSS(t *testing.T) {
	// 构造测试树 (2 of (0, 0, 2 of (0, 0,0)))
	// 1. PVGSSSetup
	num := 5
	SK := make([]*big.Int, num)
	PK1 := make([]*bn128.G1, num)
	PK2 := make([]*bn128.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}
	AA := &gss.Node{
		IsLeaf:      false,
		Childrennum: 3,
		T:           2,
		Idx:         big.NewInt(0),
		Children: []*gss.Node{
			{IsLeaf: true, Idx: big.NewInt(1)}, // 叶子节点
			{IsLeaf: true, Idx: big.NewInt(2)}, // 叶子节点
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
	// secret
	s, _ := rand.Int(rand.Reader, bn128.Order)
	// 2. PVGSSShare
	C, prfs, err := PVGSSShare(s, AA, PK1)
	if err != nil {
		t.Fatalf("pvgss failed to share: %v\n", err)
	}

	I0 := make([]int, 2)
	I0[0] = 0
	I0[1] = 1
	// 3. PVGSSVerify
	isShareValid, err := PVGSSVerify(C, prfs, AA, PK1, I0)
	if err != nil || isShareValid == false {
		t.Fatalf("pvgss share verify failed: %v\n", err)
	}
	fmt.Println("isShareValid : ", isShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		decShares[i], err = PVGSSPreRecon(C[i], SK[i])
		if err != nil {
			t.Fatalf("pvgss share decryption failed: %v\n", err)
		}
	}

	// 5. PVGSSKeyVrf
	isKeyValid := make([]bool, num)
	for i := 0; i < num; i++ {
		isKeyValid[i], err = PVGSSKeyVrf(C[i], decShares[i], PK2[i])
		if err != nil || isKeyValid[i] == false {
			t.Fatalf("pvgss share decryption verify failed: %v\n", err)
		}
	}
	fmt.Println("isKeyValidRes : ", isKeyValid)

	onrgnS := new(bn128.G1).ScalarBaseMult(s)

	// 6. PVGSSRecon
	// A and B
	I1 := I0
	Q1 := make([]*bn128.G1, 2)
	Q1[0] = decShares[0] //A's share
	Q1[1] = decShares[1] //B's share
	reconS1, _ := PVGSSRecon(AA, Q1, I1)

	assert.Equal(t, onrgnS.String(), reconS1.String())
	if onrgnS.String() == reconS1.String() {
		fmt.Print("A and B reconstruct secret secessfully!\n")
	}

	// A and Watchers
	I2 := make([]int, 3)
	I2[0] = 0
	I2[1] = 2
	I2[2] = 3
	Q2 := make([]*bn128.G1, 3)
	Q2[0] = decShares[0]
	Q2[1] = decShares[2]
	Q2[2] = decShares[3]

	reconS2, _ := PVGSSRecon(AA, Q2, I2)
	assert.Equal(t, onrgnS.String(), reconS2.String())
	if onrgnS.String() == reconS2.String() {
		fmt.Print("A and Watchers reconstruct secret secessfully!\n")
	}

	// B and Watchers
	I3 := make([]int, 3)
	I3[0] = 1
	I3[1] = 2
	I3[2] = 3
	Q3 := make([]*bn128.G1, 3)
	Q3[0] = decShares[1]
	Q3[1] = decShares[2]
	Q3[2] = decShares[3]

	reconS3, _ := PVGSSRecon(AA, Q3, I3)
	assert.Equal(t, onrgnS.String(), reconS3.String())
	if onrgnS.String() == reconS3.String() {
		fmt.Print("B and Watchers reconstruct secret secessfully!\n")
	}
}
