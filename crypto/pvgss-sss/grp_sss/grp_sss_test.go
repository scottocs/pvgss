package grp_sss

import (
	"crypto/rand"
	"fmt"

	"math/big"
	bn128 "pvgss/bn128"
	"testing"
	// "time"
)

func TestGss(t *testing.T) {
	// 1.设置原始秘密值
	s, _ := rand.Int(rand.Reader, bn128.Order)
	S := new(bn128.G1).ScalarBaseMult(s)
	fmt.Println("orignal secret = ", S)

	// 2.设置参数
	n := 5
	threshold := 3

	// 3.调用GrpShare生成份额
	shares, err := GrpShare(S, n, threshold)
	if err != nil {
		t.Fatalf("Error in GrpShare: %v", err)
	}

	// 4.生成份额对应的下标
	I := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = big.NewInt(int64(i + 1))
	}

	// 5.计算拉格朗日系数
	// lambdas, err := PrecomputeLagrangeCoefficients(I)
	// if err != nil {
	// 	t.Fatalf("Error in PrecomputeLagrangeCoefficients: %v", err)
	// }

	// 6.调用GrpRecon重构秘密
	Secret, err := GrpRecon(shares[:threshold], I)
	if err != nil {
		t.Fatalf("Error in GrpRecon: %v", err)
	}
	fmt.Println("recover secret = ", Secret)

	// 7. 验证重建的秘密与原始秘密是否相同
	if S.String() != Secret.String() {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
