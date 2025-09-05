// bench.go v4 — шардированный бенч LOGOS: Ed25519-подписи, батчи, accepted TPS.
// ENV:
//   BASE=http://127.0.0.1:8080           # или https://host/api
//   N=10000 SHARDS=4 BATCH=50 AMOUNT=1   # всего N tx, шардов (RID) S, размер пачки K
//   FAUCET=1                              # начислить перед тестом
//   USE_DEBUG_CANON=0                     # 0 = строим канон локально (быстрее), 1 = через /debug_canon
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ----- helpers -----
func b58encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	if x.Sign() == 0 { return "1" }
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for x.Cmp(zero) > 0 {
		x.QuoRem(x, base, mod)
		out = append(out, ALPH[mod.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { out[i], out[j] = out[j], out[i] }
	zeros := 0; for _, v := range b { if v==0 { zeros++ } else { break } }
	if zeros>0 { return string(bytes.Repeat([]byte("1"), zeros)) + string(out) }
	return string(out)
}
func envOr(k, d string) string { v:=os.Getenv(k); if v=="" { return d }; return v }
func httpc() *http.Client { return &http.Client{ Timeout: 20 * time.Second } }

type httpErr struct{ code int; body string }
func reqJSON(ctx context.Context, c *http.Client, method, url string, body any, out any) *httpErr {
	var rdr io.Reader
	if body != nil { b,_ := json.Marshal(body); rdr = bytes.NewReader(b) }
	req,_ := http.NewRequestWithContext(ctx, method, url, rdr)
	req.Header.Set("Content-Type","application/json")
	resp, err := c.Do(req)
	if err != nil { return &httpErr{code:0, body:err.Error()} }
	defer resp.Body.Close()
	rb,_ := io.ReadAll(resp.Body)
	if resp.StatusCode<200 || resp.StatusCode>=300 { return &httpErr{code:resp.StatusCode, body:string(rb)} }
	if out != nil { if err := json.Unmarshal(rb, out); err != nil { return &httpErr{code:-1, body:"decode:"+err.Error()} } }
	return nil
}

// CanonTx — точный порядок полей как на сервере
type CanonTx struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
	Nonce  uint64 `json:"nonce"`
}

// локальная канонизация (совпадает с серверной)
func localCanonHex(tx CanonTx) string {
	b, _ := json.Marshal(tx) // порядок полей = порядок в struct
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)
	return string(dst)
}

func main() {
	base := envOr("BASE", "http://127.0.0.1:8080")
	N, _ := strconv.Atoi(envOr("N", "10000"))
	S, _ := strconv.Atoi(envOr("SHARDS", "4"))
	K, _ := strconv.Atoi(envOr("BATCH", "50"))
	amt, _ := strconv.ParseUint(envOr("AMOUNT", "1"), 10, 64)
	faucet := os.Getenv("FAUCET")=="1"
	useDebugCanon := os.Getenv("USE_DEBUG_CANON")=="1"

	if S <= 0 { S=1 }
	if K <= 0 { K=1 }

	// распределим N по шардовым потокам
	per := N / S
	rem := N % S

	type shard struct{
		sk ed25519.PrivateKey
		rid string
		next uint64
	}

	cli := httpc()
	ctx := context.Background()

	shards := make([]shard, S)
	// подготовка шардов: генерим ключ, RID, faucet, читаем nonce
	for i:=0; i<S; i++ {
		_, sk, _ := ed25519.GenerateKey(rand.Reader)
		pk := sk.Public().(ed25519.PublicKey)
		rid := b58encode(pk)

		if faucet {
			_ = reqJSON(ctx, cli, "POST", base+"/faucet", map[string]any{
				"rid": rid, "amount": 1_000_000_000,
			}, nil)
		}

		var bal struct{ Rid string; Balance uint64; Nonce uint64 }
		if err := reqJSON(ctx, cli, "GET", base+"/balance/"+rid, nil, &bal); err != nil {
			fmt.Println("balance ERR:", err.code, err.body); os.Exit(1)
		}
		shards[i] = shard{ sk: sk, rid: rid, next: bal.Nonce+1 }
	}

	var accepted int64
	var rejected int64
	var http429 int64
	var httpErr int64

	wg := sync.WaitGroup{}
	start := time.Now()

	for i:=0; i<S; i++ {
		count := per; if i < rem { count++ }
		if count == 0 { continue }

		sh := shards[i]
		wg.Add(1)
		go func(cnt int, sh shard){
			defer wg.Done()
			loc := httpc()
			remain := cnt
			nonce := sh.next

			for remain > 0 {
				bsize := K; if remain < K { bsize = remain }
				// готовим пачку детерминированно: nonce..nonce+bsize-1
				txs := make([]map[string]any, 0, bsize)
				for j:=0; j<bsize; j++ {
					tx := CanonTx{ From: sh.rid, To: sh.rid, Amount: amt, Nonce: nonce+uint64(j) }
					var canonHex string
					if useDebugCanon {
						var canon map[string]string
						if err := reqJSON(ctx, loc, "POST", base+"/debug_canon", map[string]any{"tx": tx}, &canon); err != nil {
							if err.code==429 { atomic.AddInt64(&http429,1) } else { atomic.AddInt64(&httpErr,1) }
							return
						}
						canonHex = canon["canon_hex"]
					} else {
						canonHex = localCanonHex(tx)
					}
					cbytes, _ := hex.DecodeString(canonHex)
					sig := ed25519.Sign(sh.sk, cbytes)
					sigHex := hex.EncodeToString(sig)
					txs = append(txs, map[string]any{
						"from": tx.From, "to": tx.To, "amount": tx.Amount, "nonce": tx.Nonce, "sig_hex": sigHex,
					})
				}

				// шлём батч
				var out struct{
					Accepted int `json:"accepted"`
					Rejected int `json:"rejected"`
					NewHeight uint64 `json:"new_height"`
					Results []struct{
						Status string `json:"status"`
						Code   int    `json:"code"`
						Reason string `json:"reason"`
					} `json:"results"`
				}
				if err := reqJSON(ctx, loc, "POST", base+"/submit_tx_batch", map[string]any{"txs":txs}, &out); err != nil {
					if err.code==429 { atomic.AddInt64(&http429,1) } else { atomic.AddInt64(&httpErr,1) }
					return
				}
				atomic.AddInt64(&accepted, int64(out.Accepted))
				atomic.AddInt64(&rejected, int64(out.Rejected))

				nonce += uint64(bsize)
				remain -= bsize
			}
		}(count, sh)
	}

	wg.Wait()
	dt := time.Since(start).Seconds()
	fmt.Printf("=== DONE: accepted=%d / N=%d shards=%d batch=%d in %.2fs → ~%.1f tx/s | rejected=%d 429=%d httpErr=%d ===\n",
		accepted, N, S, K, dt, float64(accepted)/dt, rejected, http429, httpErr)
}
