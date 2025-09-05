// main.go — самоcтоятельный smoke-клиент для LOGOS LRB (без внешних зависимостей).
// Использование:
//   BASE=http://127.0.0.1:8080 go run ./main.go
//   BASE=https://45-159-248-232.sslip.io/api go run ./main.go
// Переменные:
//   RID=<base58>            # для запроса баланса
//   TO=<base58>             # для пробного submit (ожидаемая ошибка из-за фиктивной подписи)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Healthz struct{ Status string `json:"status"` }
type HeadResp struct {
	Height    uint64 `json:"height"`
	Finalized bool   `json:"finalized"`
}
type BalanceResp struct {
	Rid     string `json:"rid"`
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

func baseURL() string {
	b := os.Getenv("BASE")
	if b == "" {
		b = "http://127.0.0.1:8080"
	}
	// убрать завершающий слэш, чтобы не было двойных //
	if b[len(b)-1] == '/' {
		b = b[:len(b)-1]
	}
	return b
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func reqJSON(ctx context.Context, method, url string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, rdr)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode failed: %w", err)
		}
	}
	return nil
}

func main() {
	ctx := context.Background()
	base := baseURL()
	fmt.Println("[*] BASE =", base)

	// /healthz
	var hz Healthz
	if err := reqJSON(ctx, "GET", base+"/healthz", nil, &hz); err != nil {
		fmt.Println("healthz ERR:", err)
		os.Exit(1)
	}
	fmt.Println("[*] healthz:", hz.Status)

	// /head
	var head HeadResp
	if err := reqJSON(ctx, "GET", base+"/head", nil, &head); err != nil {
		fmt.Println("head ERR:", err)
		os.Exit(1)
	}
	fmt.Printf("[*] head: height=%d finalized=%v\n", head.Height, head.Finalized)

	// /balance/:rid (если задан RID)
	if rid := os.Getenv("RID"); rid != "" {
		var bal BalanceResp
		if err := reqJSON(ctx, "GET", base+"/balance/"+rid, nil, &bal); err != nil {
			fmt.Println("balance ERR:", err)
			os.Exit(1)
		}
		j, _ := json.Marshal(bal)
		fmt.Println("[*] balance:", string(j))

		// /debug_canon + /submit_tx_batch (smoke) если задан TO
		if to := os.Getenv("TO"); to != "" {
			// берём nonce из /balance (следующий будет +1)
			nextNonce := bal.Nonce + 1
			canonReq := map[string]any{"tx": map[string]any{
				"from": rid, "to": to, "amount": 1, "nonce": nextNonce,
			}}
			var canonResp map[string]string
			if err := reqJSON(ctx, "POST", base+"/debug_canon", canonReq, &canonResp); err != nil {
				fmt.Println("debug_canon ERR:", err)
				os.Exit(1)
			}
			fmt.Println("[*] canon_hex bytes:", len(canonResp["canon_hex"])/2)

			// Отправляем фиктивную подпись "00" — ожидаем ошибку (проверяем обработку ошибок API)
			batch := map[string]any{"txs": []map[string]any{
				{"from": rid, "to": to, "amount": 1, "nonce": nextNonce, "sig_hex": "00"},
			}}
			var out any
			if err := reqJSON(ctx, "POST", base+"/submit_tx_batch", batch, &out); err != nil {
				fmt.Println("[*] submit expected ERR:", err)
			} else {
				j, _ := json.Marshal(out)
				fmt.Println("[*] submit resp:", string(j))
			}
		}
	} else {
		fmt.Println("[i] RID не задан (RID=<base58>) — пропускаю /balance и submit.")
	}

	fmt.Println("OK")
}
