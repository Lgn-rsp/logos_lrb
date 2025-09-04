package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-tron/base58/base58"
)

/*
Нагрузчик батчей с корректной подписью:
— на каждую tx запрашивает у ноды /debug_canon (canon_hex) и подписывает её,
— отправляет на /submit_tx_batch,
— учитывает частичные приёмы (accepted < batch).
*/

type SubmitTx struct {
	From          string `json:"from"`
	To            string `json:"to"`
	Amount        uint64 `json:"amount"`
	Nonce         uint64 `json:"nonce"`
	PubKeyB58     string `json:"public_key_b58"`
	SignatureB64  string `json:"signature_b64"`
}
type DebugCanonReq struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Amount       uint64 `json:"amount"`
	Nonce        uint64 `json:"nonce"`
	PublicKeyB58 string `json:"public_key_b58"`
}
type DebugCanonResp struct {
	CanonHex   string `json:"canon_hex"`
	ServerTxID string `json:"server_tx_id"`
}
type BatchResp struct {
	Accepted          int `json:"accepted"`
	Rejected          int `json:"rejected"`
	LGNCostMicrounits int `json:"lgn_cost_microunits"`
}

func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }

func postJSON(cli *http.Client, url string, payload any) (*http.Response, []byte, error) {
	j, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil { return nil, nil, err }
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body, nil
}

func fetchCanon(cli *http.Client, node string, r DebugCanonReq) ([]byte, string, error) {
	resp, body, err := postJSON(cli, node+"/debug_canon", r)
	if err != nil { return nil, "", err }
	if resp.StatusCode/100 != 2 {
		return nil, "", fmt.Errorf("debug_canon status=%d body=%s", resp.StatusCode, string(body))
	}
	var dc DebugCanonResp
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, "", err
	}
	raw, err := hex.DecodeString(dc.CanonHex)
	if err != nil { return nil, "", fmt.Errorf("bad canon_hex: %v", err) }
	return raw, dc.ServerTxID, nil
}

func sleepToRate(start time.Time, sent uint64, rate int) {
	if rate <= 0 { return }
	elapsed := time.Since(start)
	should := time.Duration(float64(sent)/float64(rate) * float64(time.Second))
	if should > elapsed { time.Sleep(should - elapsed) }
}

func main() {
	node := flag.String("node", "http://127.0.0.1:8080", "LOGOS node base URL")
	concurrency := flag.Int("c", 200, "concurrency (workers)")
	dur := flag.Duration("d", time.Minute, "test duration")
	rate := flag.Int("rate", 5000, "target submit rate (tx/s)")
	amount := flag.Uint64("amount", 1, "tx amount (μLGN)")
	nonce0 := flag.Uint64("nonce0", 1, "starting nonce")
	faucet := flag.Uint64("faucet", 5_000_000, "faucet top-up for RID_A (DEV)")
	batch := flag.Int("batch", 100, "batch size for /submit_tx_batch")
	flag.Parse()

	fmt.Println("NODE   :", *node)
	fmt.Println("CONC   :", *concurrency)
	fmt.Println("DUR    :", *dur)
	fmt.Println("RATE   :", *rate, "tx/s")
	fmt.Println("AMOUNT :", *amount)
	fmt.Println("NONCE0 :", *nonce0)
	fmt.Println("FAUCET :", *faucet)
	fmt.Println("BATCH  :", *batch)

	// ключи A (отправитель) и B (получатель)
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubA := privA.Public().(ed25519.PublicKey)
	RID_A := base58.Encode(pubA)

	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	_ = privB
	pubB := privB.Public().(ed25519.PublicKey)
	RID_B := base58.Encode(pubB)

	fmt.Println("[*] RID_A:", RID_A)
	fmt.Println("[*] RID_B:", RID_B)

	cli := &http.Client{ Timeout: 10 * time.Second }

	// faucet
	if *faucet > 0 {
		furl := fmt.Sprintf("%s/faucet/%s/%d", *node, RID_A, *faucet)
		resp, err := cli.Post(furl, "application/json", nil)
		if err != nil { fmt.Println("[!] faucet error:", err); os.Exit(1) }
		io.Copy(io.Discard, resp.Body); resp.Body.Close()
	}

	// дросселирование
	per := time.Second / time.Duration(*rate)
	if per == 0 { per = time.Millisecond }

	start := time.Now()
	stopAt := start.Add(*dur)

	// разнести nonce по потокам
	nonceStride := uint64(1 << 32)
	rOff, _ := rand.Int(rand.Reader, big.NewInt(int64(nonceStride)))
	baseOffset := uint64(rOff.Int64())

	var sent, ok uint64
	var wg sync.WaitGroup
	wg.Add(*concurrency)

	var barrier sync.WaitGroup
	barrier.Add(*concurrency)

	var firstErrOnce sync.Once

	for w := 0; w < *concurrency; w++ {
		w := w
		go func() {
			defer wg.Done()
			barrier.Done()
			barrier.Wait()

			localNonce := *nonce0 + baseOffset + uint64(w)*nonceStride
			timer := time.NewTimer(per)

			for time.Now().Before(stopAt) {
				k := *batch
				if k < 1 { k = 1 }

				reqs := make([]SubmitTx, 0, k)
				for i := 0; i < k; i++ {
					n := localNonce + uint64(i)
					// 1) canon от сервера
					dcReq := DebugCanonReq{
						From: RID_A, To: RID_B, Amount: *amount, Nonce: n,
						PublicKeyB58: base58.Encode(pubA),
					}
					canon, _, err := fetchCanon(cli, *node, dcReq)
					if err != nil {
						firstErrOnce.Do(func() { fmt.Println("[!] debug_canon error:", err) })
						continue
					}
					// 2) подпись
					sig := ed25519.Sign(privA, canon)
					reqs = append(reqs, SubmitTx{
						From: RID_A, To: RID_B, Amount: *amount, Nonce: n,
						PubKeyB58: base58.Encode(pubA),
						SignatureB64: base64.StdEncoding.EncodeToString(sig),
					})
				}

				if len(reqs) == 0 {
					// троттлинг
					select {
					case <-timer.C:
						timer.Reset(per)
					default:
						sleepToRate(start, atomic.LoadUint64(&sent), *rate)
					}
					continue
				}

				// отправка батча
				resp, body, err := postJSON(cli, *node+"/submit_tx_batch", reqs)
				atomic.AddUint64(&sent, uint64(len(reqs)))

				if err != nil {
					firstErrOnce.Do(func() { fmt.Println("[!] batch post error:", err) })
				} else if resp.StatusCode/100 == 2 {
					var br BatchResp
					if json.Unmarshal(body, &br) == nil {
						atomic.AddUint64(&ok, uint64(br.Accepted)) // NEW: учитываем частичный приём
					} else {
						// если не распарсили, считаем всё принято (редко)
						atomic.AddUint64(&ok, uint64(len(reqs)))
					}
				} else {
					firstErrOnce.Do(func() {
						fmt.Printf("[!] submit_tx_batch status=%d body=%s\n", resp.StatusCode, string(body))
					})
				}

				localNonce += uint64(len(reqs))

				// троттлинг
				select {
				case <-timer.C:
					timer.Reset(per)
				default:
					sleepToRate(start, atomic.LoadUint64(&sent), *rate)
				}
			}
		}()
	}

	wg.Wait()
	el := time.Since(start).Seconds()
	total := atomic.LoadUint64(&sent)
	okCnt := atomic.LoadUint64(&ok)
	rps := float64(total) / math.Max(el, 0.001)
	fmt.Printf("\n=== RESULT ===\n sent=%d ok=%d err=%d  (elapsed=%.1fs, ~%.0f tx/s)\n", total, okCnt, total-okCnt, el, rps)
}
