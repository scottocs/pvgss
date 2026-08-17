package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	bn128 "pvgss/bn128"
	Dex "pvgss/compile/contract/Dex"
	PVETH "pvgss/compile/contract/PVETH"
	PVUSDT "pvgss/compile/contract/PVUSDT"
	"pvgss/crypto/dleq"
	lssspvgss "pvgss/crypto/lssspvgss"
	"pvgss/crypto/lssspvgss/lsss"
	"pvgss/crypto/node"
	ssspvgss "pvgss/crypto/ssspvgss"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/joho/godotenv"
)

type gasRow struct {
	Figure    string
	Scheme    string
	N         int
	Operation string
	Gas       uint64
	TxHash    common.Hash
}

type env struct {
	ctx        context.Context
	eth        *ethclient.Client
	rpc        *rpc.Client
	keys       []string
	dexAddr    common.Address
	pvethAddr  common.Address
	pvusdtAddr common.Address
	dex        *Dex.Dex
	allSK      []*big.Int
	allPK      []*bn128.G1
	register   *gasRow
}

func main() {
	rpcURL := flag.String("rpc", "ws://127.0.0.1:8545", "local Ethereum JSON-RPC endpoint")
	outPath := flag.String("out", "paper/dex_gas.csv", "CSV output path")
	nValues := flag.String("n", "1,4,7,10,13,16,19,22,25,28", "comma-separated watcher counts")
	schemes := flag.String("schemes", "lsss-exact,sss-exact,lsss-dual,sss-dual", "comma-separated schemes: lsss-exact,sss-exact,lsss-dual,sss-dual")
	flag.Parse()

	must(godotenv.Load(".env"))
	ns, err := parseInts(*nValues)
	must(err)
	schemeList := parseStrings(*schemes)

	e := newEnv(*rpcURL, maxN(ns)+2)
	e.deployAndPrepare()

	f, err := os.Create(*outPath)
	must(err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	must(w.Write([]string{"figure", "scheme", "n", "operation", "gas", "tx_hash"}))
	writeRow := func(row gasRow) {
		must(w.Write([]string{
			row.Figure,
			row.Scheme,
			strconv.Itoa(row.N),
			row.Operation,
			strconv.FormatUint(row.Gas, 10),
			row.TxHash.Hex(),
		}))
	}
	if e.register != nil {
		writeRow(*e.register)
	}

	orderID := big.NewInt(0)
	for _, n := range ns {
		for _, scheme := range schemeList {
			rows := e.runScenario(scheme, n, new(big.Int).Set(orderID))
			for _, row := range rows {
				writeRow(row)
			}
			w.Flush()
			must(w.Error())
			orderID.Add(orderID, big.NewInt(1))
		}
	}
}

func newEnv(rpcURL string, minAccounts int) *env {
	ctx := context.Background()
	rpcClient, err := rpc.DialContext(ctx, rpcURL)
	must(err)
	eth := ethclient.NewClient(rpcClient)

	keys := loadKeys(ctx, rpcClient, max(20, minAccounts))
	return &env{ctx: ctx, eth: eth, rpc: rpcClient, keys: keys}
}

func (e *env) deployAndPrepare() {
	dexAddr, tx, dex, err := Dex.DeployDex(e.auth(3, big.NewInt(0)), e.eth)
	must(err)
	e.wait(tx)
	pvethAddr, tx, pveth, err := PVETH.DeployPVETH(e.auth(0, big.NewInt(0)), e.eth)
	must(err)
	e.wait(tx)
	pvusdtAddr, tx, pvusdt, err := PVUSDT.DeployPVUSDT(e.auth(1, big.NewInt(0)), e.eth)
	must(err)
	e.wait(tx)

	e.dexAddr = dexAddr
	e.pvethAddr = pvethAddr
	e.pvusdtAddr = pvusdtAddr
	e.dex = dex

	e.allSK, e.allPK = sssKeys(len(e.keys))
	for i := range e.keys {
		tx, err := e.dex.Register(e.auth(i, big.NewInt(0)), g1ToPoint(e.allPK[i]))
		must(err)
		receipt := e.wait(tx)
		if i == 0 {
			e.register = &gasRow{"table3", "DEX", 0, "register", receipt.GasUsed, receipt.TxHash}
		}
	}
	for i := range e.keys {
		tx, err := e.dex.StakeETH(e.auth(i, mustDecimal("9000000000000000000")), i > 1)
		must(err)
		e.wait(tx)
	}

	amountETH := mustDecimal("10000000000000000000")
	tx, err = pveth.Approve(e.auth(0, big.NewInt(0)), e.dexAddr, amountETH)
	must(err)
	e.wait(tx)
	tx, err = e.dex.Deposit(e.auth(0, big.NewInt(0)), e.pvethAddr, amountETH)
	must(err)
	e.wait(tx)

	amountUSDT := mustDecimal("10000000000000000000000")
	tx, err = pvusdt.Approve(e.auth(1, big.NewInt(0)), e.dexAddr, amountUSDT)
	must(err)
	e.wait(tx)
	tx, err = e.dex.Deposit(e.auth(1, big.NewInt(0)), e.pvusdtAddr, amountUSDT)
	must(err)
	e.wait(tx)
}

func (e *env) runScenario(scheme string, n int, orderID *big.Int) []gasRow {
	mustTx := func(tx *types.Transaction, err error) *types.Receipt {
		must(err)
		return e.wait(tx)
	}

	amountSell := mustDecimal("10000000000000000")
	amountBuy := mustDecimal("30000000000000000000")
	createReceipt := mustTx(e.dex.CreateOrder(e.auth(0, big.NewInt(0)), e.pvethAddr, amountSell, e.pvusdtAddr, amountBuy))
	acceptReceipt := mustTx(e.dex.AcceptOrder(e.auth(1, big.NewInt(0)), orderID, big.NewInt(int64(n)), big.NewInt(1)))

	var rows []gasRow
	switch scheme {
	case "lsss", "lsss-exact":
		rows = e.runLSSS(n, orderID, false)
	case "sss", "sss-exact":
		rows = e.runSSS(n, orderID, false)
	case "lsss-dual":
		rows = e.runLSSS(n, orderID, true)
	case "sss-dual":
		rows = e.runSSS(n, orderID, true)
	default:
		panic("unknown scheme: " + scheme)
	}
	schemeName := rows[0].Scheme
	return append([]gasRow{
		{"table3", schemeName, n, "create_order", createReceipt.GasUsed, createReceipt.TxHash},
		{"table3", schemeName, n, "accept_order", acceptReceipt.GasUsed, acceptReceipt.TxHash},
	}, rows...)
}

func (e *env) runLSSS(n int, orderID *big.Int, dual bool) []gasRow {
	scheme := "LSSS-based with Exact interpolation test"
	if dual {
		scheme = "LSSS-based with Dual code test"
	}
	root, _, _ := dexAccessTree(n, 1)
	num := n + 2
	sk, pk := e.keySlice(num)
	sellerC, sellerProof, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	buyerC, buyerProof, err := lssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	matrix := lsss.Convert(root)
	i0 := []int{0, 1}
	i1 := []int{0, 2}
	w0, err := lsss.ReconstructionWeightsForRows(matrix, i0)
	must(err)
	w1, err := lsss.ReconstructionWeightsForRows(matrix, i1)
	must(err)
	sellerDec, sellerOpeningProofs := lsssPreReconAll(sellerC, sk)
	buyerDec, buyerOpeningProofs := lsssPreReconAll(buyerC, sk)
	mustReceipt := e.waitMust(e.dex.CreatePath(e.auth(0, big.NewInt(0)), big.NewInt(int64(n)), big.NewInt(1), big.NewInt(4)))
	_ = mustReceipt

	var r1, r2 *types.Receipt
	if dual {
		r1 = e.waitMust(e.dex.Lswap1Dual(e.auth(1, big.NewInt(0)), orderID, g1sToPoints(buyerProof.Cp), buyerProof.Xc, buyerProof.Shat, buyerProof.Shatarry, g1sToPoints(buyerC), g1sToPoints(pk), w0, w1, intsToBig(i0), intsToBig(i1)))
		r2 = e.waitMust(e.dex.Lswap1Dual(e.auth(0, big.NewInt(0)), orderID, g1sToPoints(sellerProof.Cp), sellerProof.Xc, sellerProof.Shat, sellerProof.Shatarry, g1sToPoints(sellerC), g1sToPoints(pk), w0, w1, intsToBig(i0), intsToBig(i1)))
	} else {
		r1 = e.waitMust(e.dex.Lswap1(e.auth(1, big.NewInt(0)), orderID, g1sToPoints(buyerProof.Cp), buyerProof.Xc, buyerProof.Shat, buyerProof.Shatarry, g1sToPoints(buyerC), g1sToPoints(pk), w0, w1, intsToBig(i0), intsToBig(i1)))
		r2 = e.waitMust(e.dex.Lswap1(e.auth(0, big.NewInt(0)), orderID, g1sToPoints(sellerProof.Cp), sellerProof.Xc, sellerProof.Shat, sellerProof.Shatarry, g1sToPoints(sellerC), g1sToPoints(pk), w0, w1, intsToBig(i0), intsToBig(i1)))
	}
	r3 := e.waitMust(e.dex.Swap2(e.auth(0, big.NewInt(0)), orderID, g1ToPoint(sellerDec[0]), g1ToPoint(sellerOpeningProofs[0].C1), g1ToPoint(sellerOpeningProofs[0].C2), sellerOpeningProofs[0].Challenge, sellerOpeningProofs[0].Response))

	e.increaseTime(31)
	r4 := e.waitMust(e.dex.Complain(e.auth(0, big.NewInt(0)), orderID))
	r5 := e.waitMust(e.dex.SubmitWatcherShare(e.auth(2, big.NewInt(0)), orderID, g1ToPoint(buyerDec[2]), g1ToPoint(buyerOpeningProofs[2].C1), g1ToPoint(buyerOpeningProofs[2].C2), buyerOpeningProofs[2].Challenge, buyerOpeningProofs[2].Response))
	r6 := e.waitMust(e.dex.Determine(e.auth(1, big.NewInt(0)), orderID))

	return []gasRow{
		{"17", scheme, n, "counterparty_lswap1", r1.GasUsed, r1.TxHash},
		{"17", scheme, n, "swap1_plus_swap2", r2.GasUsed + r3.GasUsed, r2.TxHash},
		{"17", scheme, n, "lswap1", r2.GasUsed, r2.TxHash},
		{"18", scheme, n, "swap2", r5.GasUsed, r5.TxHash},
		{"18", scheme, n, "complain", r4.GasUsed, r4.TxHash},
		{"18", scheme, n, "determine", r6.GasUsed, r6.TxHash},
	}
}

func (e *env) runSSS(n int, orderID *big.Int, dual bool) []gasRow {
	scheme := "Shamir SS-based with Exact interpolation test"
	if dual {
		scheme = "Shamir SS-based with Dual code test"
	}
	root, _, _ := dexAccessTree(n, 1)
	num := n + 2
	sk, pk := e.keySlice(num)
	sellerC, sellerProof, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	buyerC, buyerProof, err := ssspvgss.PVGSSShare(randomScalar(), root, pk)
	must(err)
	sellerDec, sellerOpeningProofs := sssPreReconAll(sellerC, sk)
	buyerDec, buyerOpeningProofs := sssPreReconAll(buyerC, sk)
	mustReceipt := e.waitMust(e.dex.CreatePath(e.auth(0, big.NewInt(0)), big.NewInt(int64(n)), big.NewInt(1), big.NewInt(4)))
	_ = mustReceipt
	vrfQ := make([]*big.Int, 3)
	for i := range vrfQ {
		vrfQ[i] = big.NewInt(int64(i))
	}

	var r1, r2 *types.Receipt
	if dual {
		r1 = e.waitMust(e.dex.Swap1Dual(e.auth(1, big.NewInt(0)), orderID, g1sToPoints(buyerProof.Cp), buyerProof.Xc, buyerProof.Shat, buyerProof.Shatarry, g1sToPoints(buyerC), g1sToPoints(pk), vrfQ))
		r2 = e.waitMust(e.dex.Swap1Dual(e.auth(0, big.NewInt(0)), orderID, g1sToPoints(sellerProof.Cp), sellerProof.Xc, sellerProof.Shat, sellerProof.Shatarry, g1sToPoints(sellerC), g1sToPoints(pk), vrfQ))
	} else {
		r1 = e.waitMust(e.dex.Swap1(e.auth(1, big.NewInt(0)), orderID, g1sToPoints(buyerProof.Cp), buyerProof.Xc, buyerProof.Shat, buyerProof.Shatarry, g1sToPoints(buyerC), g1sToPoints(pk), vrfQ))
		r2 = e.waitMust(e.dex.Swap1(e.auth(0, big.NewInt(0)), orderID, g1sToPoints(sellerProof.Cp), sellerProof.Xc, sellerProof.Shat, sellerProof.Shatarry, g1sToPoints(sellerC), g1sToPoints(pk), vrfQ))
	}
	r3 := e.waitMust(e.dex.Swap2(e.auth(0, big.NewInt(0)), orderID, g1ToPoint(sellerDec[0]), g1ToPoint(sellerOpeningProofs[0].C1), g1ToPoint(sellerOpeningProofs[0].C2), sellerOpeningProofs[0].Challenge, sellerOpeningProofs[0].Response))

	e.increaseTime(31)
	r4 := e.waitMust(e.dex.Complain(e.auth(0, big.NewInt(0)), orderID))
	r5 := e.waitMust(e.dex.SubmitWatcherShare(e.auth(2, big.NewInt(0)), orderID, g1ToPoint(buyerDec[2]), g1ToPoint(buyerOpeningProofs[2].C1), g1ToPoint(buyerOpeningProofs[2].C2), buyerOpeningProofs[2].Challenge, buyerOpeningProofs[2].Response))
	r6 := e.waitMust(e.dex.Determine(e.auth(1, big.NewInt(0)), orderID))

	return []gasRow{
		{"17", scheme, n, "counterparty_swap1", r1.GasUsed, r1.TxHash},
		{"17", scheme, n, "swap1_plus_swap2", r2.GasUsed + r3.GasUsed, r2.TxHash},
		{"17", scheme, n, "swap1", r2.GasUsed, r2.TxHash},
		{"18", scheme, n, "swap2", r5.GasUsed, r5.TxHash},
		{"18", scheme, n, "complain", r4.GasUsed, r4.TxHash},
		{"18", scheme, n, "determine", r6.GasUsed, r6.TxHash},
	}
}

func (e *env) auth(i int, value *big.Int) *bind.TransactOpts {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(e.keys[i], "0x"))
	must(err)
	publicKey := key.Public()
	publicKeyECDSA := publicKey.(*ecdsa.PublicKey)
	from := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := e.eth.PendingNonceAt(e.ctx, from)
	must(err)
	chainID, err := e.eth.ChainID(e.ctx)
	must(err)
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	must(err)
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = 900719925
	auth.GasPrice = big.NewInt(20_000_000_000)
	return auth
}

func (e *env) waitMust(tx *types.Transaction, err error) *types.Receipt {
	must(err)
	return e.wait(tx)
}

func (e *env) wait(tx *types.Transaction) *types.Receipt {
	receipt, err := bind.WaitMined(e.ctx, e.eth, tx)
	must(err)
	if receipt.Status != types.ReceiptStatusSuccessful {
		panic(fmt.Errorf("transaction reverted: %s", tx.Hash().Hex()))
	}
	return receipt
}

func (e *env) increaseTime(seconds int64) {
	var ignored any
	must(e.rpc.CallContext(e.ctx, &ignored, "evm_increaseTime", seconds))
	must(e.rpc.CallContext(e.ctx, &ignored, "evm_mine"))
}

func (e *env) keySlice(num int) ([]*big.Int, []*bn128.G1) {
	if num > len(e.allSK) || num > len(e.allPK) {
		panic(fmt.Errorf("need %d registered keys, have %d", num, len(e.allPK)))
	}
	return e.allSK[:num], e.allPK[:num]
}

func lsssPreReconAll(c []*bn128.G1, sk []*big.Int) ([]*bn128.G1, []*dleq.DLEQProof) {
	dec := make([]*bn128.G1, len(c))
	proofs := make([]*dleq.DLEQProof, len(c))
	for i := range c {
		var err error
		dec[i], proofs[i], err = lssspvgss.PVGSSPreRecon(c[i], sk[i])
		must(err)
	}
	return dec, proofs
}

func sssPreReconAll(c []*bn128.G1, sk []*big.Int) ([]*bn128.G1, []*dleq.DLEQProof) {
	dec := make([]*bn128.G1, len(c))
	proofs := make([]*dleq.DLEQProof, len(c))
	for i := range c {
		var err error
		dec[i], proofs[i], err = ssspvgss.PVGSSPreRecon(c[i], sk[i])
		must(err)
	}
	return dec, proofs
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

func g1ToPoint(point *bn128.G1) Dex.DexG1Point {
	pointBytes := point.Marshal()
	return Dex.DexG1Point{
		X: new(big.Int).SetBytes(pointBytes[:32]),
		Y: new(big.Int).SetBytes(pointBytes[32:64]),
	}
}

func g1sToPoints(points []*bn128.G1) []Dex.DexG1Point {
	out := make([]Dex.DexG1Point, len(points))
	for i := range points {
		out[i] = g1ToPoint(points[i])
	}
	return out
}

func intsToBig(values []int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, v := range values {
		out[i] = big.NewInt(int64(v))
	}
	return out
}

func randomScalar() *big.Int {
	s, err := rand.Int(rand.Reader, bn128.Order)
	must(err)
	return s
}

func loadKeys(ctx context.Context, rpcClient *rpc.Client, num int) []string {
	keys := make([]string, num)
	for i := range keys {
		key := os.Getenv(fmt.Sprintf("PRIVATE_KEY_%d", i+1))
		if key == "" {
			generated, err := crypto.GenerateKey()
			must(err)
			key = common.Bytes2Hex(crypto.FromECDSA(generated))
			address := crypto.PubkeyToAddress(generated.PublicKey)
			var ignored any
			must(rpcClient.CallContext(ctx, &ignored, "evm_setAccountBalance", address.Hex(), "0x3635C9ADC5DEA00000"))
		}
		keys[i] = key
	}
	return keys
}

func mustDecimal(raw string) *big.Int {
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		panic("invalid decimal: " + raw)
	}
	return n
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

func parseStrings(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func maxN(values []int) int {
	m := 0
	for _, v := range values {
		if v > m {
			m = v
		}
	}
	return m
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
