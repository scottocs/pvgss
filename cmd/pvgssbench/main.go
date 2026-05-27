package main

import (
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	bn128 "pvgss/bn128"
	"pvgss/crypto/dleq"
	lssspvgss "pvgss/crypto/lssspvgss"
	"pvgss/crypto/node"
	ssspvgss "pvgss/crypto/ssspvgss"
)

var (
	sinkBool  bool
	sinkG1    *bn128.G1
	sinkG1s   []*bn128.G1
	sinkProof any
)

type benchCase struct {
	figure    string
	scheme    string
	operation string
	n         int
	fn        func(*testing.B)
}

func main() {
	outPath := flag.String("out", "paper/bench_pvgss.csv", "CSV output path")
	nValues := flag.String("n", "100,200,300,400,500,600,700,800,900,1000", "comma-separated watcher counts")
	repeats := flag.Int("repeat", 3, "benchmark repeats per data point")
	figures := flag.String("figures", "12,13,14,15", "comma-separated figure ids to run")
	flag.Parse()

	ns, err := parseInts(*nValues)
	must(err)
	figureSet := parseSet(*figures)

	f, err := os.Create(*outPath)
	must(err)
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()
	must(w.Write([]string{"figure", "scheme", "n", "operation", "run", "iterations", "ns_per_op", "ms_per_op", "allocs_per_op"}))

	for _, n := range ns {
		cases := makeBenchCases(n)
		for _, bc := range cases {
			if !figureSet[bc.figure] {
				continue
			}
			for run := 1; run <= *repeats; run++ {
				res := testing.Benchmark(bc.fn)
				must(w.Write([]string{
					bc.figure,
					bc.scheme,
					strconv.Itoa(bc.n),
					bc.operation,
					strconv.Itoa(run),
					strconv.Itoa(res.N),
					strconv.FormatInt(res.NsPerOp(), 10),
					strconv.FormatFloat(float64(res.NsPerOp())/1e6, 'f', 6, 64),
					strconv.FormatInt(res.AllocsPerOp(), 10),
				}))
				w.Flush()
				must(w.Error())
			}
		}
	}
}

func parseSet(raw string) map[string]bool {
	parts := strings.Split(raw, ",")
	out := make(map[string]bool, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out[part] = true
		}
	}
	return out
}

func makeBenchCases(n int) []benchCase {
	return []benchCase{
		makeLSSSShareBench(n),
		makeSSSShareBench(n),
		makeLSSSVerifyExactBench(n),
		makeSSSVerifyExactBench(n),
		makeLSSSVerifyDualBench(n),
		makeSSSVerifyDualBench(n),
		makeLSSSKeyVrfBench(n),
		makeSSSKeyVrfBench(n),
		makeLSSSReconBench(n),
		makeSSSReconBench(n),
	}
}

func makeLSSSShareBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := lsssKeys(n + 2)
	secret := randomScalar()
	return benchCase{"12", "LSSS-based", "PVGSSShare", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c, proof, err := lssspvgss.PVGSSShare(secret, root, pk)
			if err != nil {
				panic(err)
			}
			sinkG1s = c
			sinkProof = proof
		}
	}}
}

func makeSSSShareBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := sssKeys(n + 2)
	secret := randomScalar()
	return benchCase{"12", "Shamir SS-based", "PVGSSShare", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c, proof, err := ssspvgss.PVGSSShare(secret, root, pk)
			if err != nil {
				panic(err)
			}
			sinkG1s = c
			sinkProof = proof
		}
	}}
}

func makeLSSSVerifyExactBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := lsssKeys(n + 2)
	c, proof, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	return benchCase{"13", "LSSS-based with Exact interpolation test", "PVGSSVerify", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := lssspvgss.PVGSSVerifyExact(c, proof, root, pk)
			if err != nil || !ok {
				panic(fmt.Errorf("PVGSSVerify failed: %v", err))
			}
			sinkBool = ok
		}
	}}
}

func makeSSSVerifyExactBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := sssKeys(n + 2)
	c, proof, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	return benchCase{"13", "Shamir SS-based with Exact interpolation test", "PVGSSVerify", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := ssspvgss.PVGSSVerifyExact(c, proof, root, pk)
			if err != nil || !ok {
				panic(fmt.Errorf("PVGSSVerify failed: %v", err))
			}
			sinkBool = ok
		}
	}}
}

func makeLSSSVerifyDualBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := lsssKeys(n + 2)
	c, proof, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	return benchCase{"13", "LSSS-based with Dual code test", "PVGSSVerify", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := lssspvgss.PVGSSVerifyDual(c, proof, root, pk)
			if err != nil || !ok {
				panic(fmt.Errorf("PVGSSVerify failed: %v", err))
			}
			sinkBool = ok
		}
	}}
}

func makeSSSVerifyDualBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	_, pk := sssKeys(n + 2)
	c, proof, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	return benchCase{"13", "Shamir SS-based with Dual code test", "PVGSSVerify", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := ssspvgss.PVGSSVerifyDual(c, proof, root, pk)
			if err != nil || !ok {
				panic(fmt.Errorf("PVGSSVerify failed: %v", err))
			}
			sinkBool = ok
		}
	}}
}

func makeLSSSKeyVrfBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	sk, pk := lsssKeys(n + 2)
	c, _, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	decShares := make([]*bn128.G1, len(c))
	proofs := make([]*dleq.DLEQProof, len(c))
	for i := range c {
		decShares[i], proofs[i], err = lssspvgss.PVGSSPreRecon(c[i], sk[i])
		must(err)
	}
	return benchCase{"14", "LSSS-based", "n*PVGSSKeyVrf", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for j := range c {
				ok, err := lssspvgss.PVGSSKeyVrf(c[j], decShares[j], pk[j], proofs[j])
				if err != nil || !ok {
					panic(fmt.Errorf("PVGSSKeyVrf failed: %v", err))
				}
				sinkBool = ok
			}
		}
	}}
}

func makeSSSKeyVrfBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	sk, pk := sssKeys(n + 2)
	c, _, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	decShares := make([]*bn128.G1, len(c))
	proofs := make([]*dleq.DLEQProof, len(c))
	for i := range c {
		decShares[i], proofs[i], err = ssspvgss.PVGSSPreRecon(c[i], sk[i])
		must(err)
	}
	return benchCase{"14", "Shamir SS-based", "n*PVGSSKeyVrf", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for j := range c {
				ok, err := ssspvgss.PVGSSKeyVrf(c[j], decShares[j], pk[j], proofs[j])
				if err != nil || !ok {
					panic(fmt.Errorf("PVGSSKeyVrf failed: %v", err))
				}
				sinkBool = ok
			}
		}
	}}
}

func makeLSSSReconBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	t := n/2 + 1
	sk, pk := lsssKeys(n + 2)
	c, _, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	q := make([]*bn128.G1, 1+t)
	indices := make([]int, 1+t)
	q[0], _, err = lssspvgss.PVGSSPreRecon(c[0], sk[0])
	must(err)
	indices[0] = 0
	for i := 1; i < 1+t; i++ {
		q[i], _, err = lssspvgss.PVGSSPreRecon(c[i+1], sk[i+1])
		must(err)
		indices[i] = i + 1
	}
	weights, err := lssspvgss.PrepareReconWeights(root, indices)
	must(err)
	return benchCase{"15", "LSSS-based", "PVGSSRecon", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, err := lssspvgss.PVGSSReconWithWeights(q, indices, weights)
			if err != nil {
				panic(err)
			}
			sinkG1 = s
		}
	}}
}

func makeSSSReconBench(n int) benchCase {
	root, _, _ := dexAccessTree(n, n/2+1)
	t := n/2 + 1
	sk, pk := sssKeys(n + 2)
	c, _, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	path := node.NewNode(false, 2, 2, big.NewInt(0))
	a := node.NewNode(true, 0, 1, big.NewInt(1))
	x := node.NewNode(false, t, t, big.NewInt(3))
	path.Children = []*node.Node{a, x}
	x.Children = make([]*node.Node, t)
	q := make([]*bn128.G1, 1+t)
	q[0], _, err = ssspvgss.PVGSSPreRecon(c[0], sk[0])
	must(err)
	for i := 0; i < t; i++ {
		x.Children[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
		q[i+1], _, err = ssspvgss.PVGSSPreRecon(c[i+2], sk[i+2])
		must(err)
	}
	weights, err := ssspvgss.PrepareReconWeights(path)
	must(err)
	_ = root
	return benchCase{"15", "Shamir SS-based", "PVGSSRecon", n, func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s, err := ssspvgss.PVGSSReconWithWeights(q, weights)
			if err != nil {
				panic(err)
			}
			sinkG1 = s
		}
	}}
}

func lsssKeys(num int) ([]*big.Int, []*bn128.G1) {
	sk := make([]*big.Int, num)
	pk := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		sk[i], pk[i] = lssspvgss.PVGSSSetup()
	}
	return sk, pk
}

func sssKeys(num int) ([]*big.Int, []*bn128.G1) {
	sk := make([]*big.Int, num)
	pk := make([]*bn128.G1, num)
	for i := 0; i < num; i++ {
		sk[i], pk[i] = ssspvgss.PVGSSSetup()
	}
	return sk, pk
}

func dexAccessTree(n, t int) (*node.Node, *node.Node, *node.Node) {
	root := node.NewNode(false, 3, 2, big.NewInt(0))
	a := node.NewNode(true, 0, 1, big.NewInt(1))
	b := node.NewNode(true, 0, 1, big.NewInt(2))
	x := node.NewNode(false, n, t, big.NewInt(3))
	root.Children = []*node.Node{a, b, x}
	x.Children = make([]*node.Node, n)
	for i := 0; i < n; i++ {
		x.Children[i] = node.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	return root, a, b
}

func randomScalar() *big.Int {
	s, err := rand.Int(rand.Reader, bn128.Order)
	must(err)
	return s
}

func parseInts(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
