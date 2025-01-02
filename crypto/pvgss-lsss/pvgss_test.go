package pvgss_lsss

import (
	"crypto/rand"
	"fmt"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGSS(t *testing.T) {
	//test GSS based on LSSS
	gss := NewGSS()

	//shareholders := []string{"holder1", "holder2", "holder3", "holder4", "holder5"}

	// create a msp struct out of the boolean formula
	msp, err := lib.BooleanToMSP("((holder1 AND holder2) OR (holder3 AND holder4)) OR holder5", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}
	//sample share s
	sampler := sample.NewUniform(gss.P)
	s, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to sample: %v\n", err)
	}

	//create shares of s
	shares, err := gss.LSSShare(s, msp)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v\n", err)
	}

	//holder1,holder2 recon
	goodShares := make([]*GSSShare, 0)
	goodShares = append(goodShares, shares[0])
	goodShares = append(goodShares, shares[1])

	reconS, err := gss.LSSSRecon(msp, goodShares)
	if err != nil {
		t.Fatalf("Error LSSSRecon: %v\n", err)
	}
	assert.Equal(t, s, reconS)

	//holder5 recon
	goodShares1 := make([]*GSSShare, 0)
	goodShares1 = append(goodShares1, shares[4])

	reconS, err = gss.LSSSRecon(msp, goodShares1)
	if err != nil {
		t.Fatalf("Error LSSSRecon: %v\n", err)
	}
	assert.Equal(t, s, reconS)

	//bad share of holder1 and holder3
	badShares := make([]*GSSShare, 0)
	badShares = append(badShares, shares[0])
	badShares = append(badShares, shares[2])

	_, err = gss.LSSSRecon(msp, badShares)
	if err != nil {
		fmt.Printf("bad share return LSSSRecon Error: %v\n", err)
	}
	assert.Error(t, err)
}

func TestGrpGSS(t *testing.T) {
	//test GrpGSS based on GrpLSSS
	grpGss := NewGrpGSS()
	//get random secret on G
	_, S, err := bn128.RandomG1(rand.Reader)

	// create a msp struct out of the boolean formula
	msp, err := lib.BooleanToMSP("((holder1 AND holder2) OR (holder3 AND holder4)) OR holder5", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}
	grpShares, err := grpGss.GrpLSSSShare(S, msp)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v\n", err)
	}

	//holder1,holder2 recon
	goodGrpShares := make([]*GrpGSSShare, 0)
	goodGrpShares = append(goodGrpShares, grpShares[0])
	goodGrpShares = append(goodGrpShares, grpShares[1])

	reconGrpS, err := grpGss.GrpLSSSRecon(msp, goodGrpShares)
	if err != nil {
		t.Fatalf("Error GrpLSSSRecon: %v\n", err)
	}
	assert.Equal(t, S.String(), reconGrpS.String())

	//holder5 recon
	goodGrpShares1 := make([]*GrpGSSShare, 0)
	goodGrpShares1 = append(goodGrpShares1, grpShares[4])

	reconGrpS, err = grpGss.GrpLSSSRecon(msp, goodGrpShares1)
	if err != nil {
		t.Fatalf("Error GrpLSSSRecon: %v\n", err)
	}
	assert.Equal(t, S.String(), reconGrpS.String())

	//bad share of holder1 and holder3
	badShares := make([]*GrpGSSShare, 0)
	badShares = append(badShares, grpShares[0])
	badShares = append(badShares, grpShares[2])

	_, err = grpGss.GrpLSSSRecon(msp, badShares)
	if err != nil {
		fmt.Printf("bad share return LSSSRecon Error: %v\n", err)
	}
	assert.Error(t, err)
}
