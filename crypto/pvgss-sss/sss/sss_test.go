package sss

import (
	"crypto/rand"
	"fmt"

	"math/big"
	bn128 "pvgss/bn128"
	"testing"
)

func TestSSS(t *testing.T) {
	// 测试参数
	n := 5         // 份额数量
	threshold := 3 // 阈值

	// 生成一个随机秘密
	s, _ := rand.Int(rand.Reader, bn128.Order)

	// 使用Share函数生成秘密的份额
	shares, err := Share(s, n, threshold)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	// 生成份额对应的下标
	I := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = big.NewInt(int64(i + 1))
	}

	// 从生成的份额中选择t个份额进行重构
	secret, err := Recon(shares[:threshold], I)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)

	// 7. 验证重建的秘密与原始秘密是否相同
	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
