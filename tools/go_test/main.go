package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	base58 "github.com/mr-tron/base58/base58"
)

// Конфиг
const defaultNode = "http://127.0.0.1:8080"

// ВАЖНО: порядок полей ДОЛЖЕН соответствовать серверу:
// amount, from, nonce, public_key, to
type canonMsg struct {
	Amount    uint64 `json:"amount"`
	From      string `json:"from"`
	Nonce     uint64 `json:"nonce"`
	PublicKey string `json:"public_key"` // base64(pk)
	To        string `json:"to"`
}

type submitTx struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Amount       uint64 `json:"amount"`
	Nonce        uint64 `json:"nonce"`
	PublicKeyB58 string `json:"public_key_b58"`
	SignatureB64 string `json:"signature_b64"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func httpJSON(method, url string, body any) ([]byte, int) {
	var reqBody io.Reader
	if body != nil {
		b := must(json.Marshal(body))
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		panic(err)
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode
}

func main() {
	node := os.Getenv("LRB_NODE")
	if node == "" {
		node = defaultNode
	}
	fmt.Println("[*] Node:", node)

	// 1) Генерим ключи Ed25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	rid := base58.Encode(pub)
	fmt.Println("[*] RID:", rid)

	// 2) Каноничное сообщение по порядку сервера
	canon := canonMsg{
		Amount:    12345,
		From:      rid,
		Nonce:     1,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		To:        rid, // отправим самому себе
	}
	canonBytes := must(json.Marshal(canon))
	fmt.Printf("[*] CANON (client hex): %x\n", canonBytes)

	// 3) Подпись
	sig := ed25519.Sign(priv, canonBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// 4) Запрос submit_tx
	req := submitTx{
		From:         canon.From,
		To:           canon.To,
		Amount:       canon.Amount,
		Nonce:        canon.Nonce,
		PublicKeyB58: base58.Encode(pub),
		SignatureB64: sigB64,
	}

	fmt.Println("[*] GET /healthz")
	hb, _ := httpJSON("GET", node+"/healthz", nil)
	fmt.Println(string(hb))

	fmt.Println("[*] GET /head (before)")
	headBefore, _ := httpJSON("GET", node+"/head", nil)
	fmt.Println(string(headBefore))

	fmt.Println("[*] POST /submit_tx")
	resp, code := httpJSON("POST", node+"/submit_tx", req)
	fmt.Println("status:", code, "body:", string(resp))

	// Подождём продюсер блока
	time.Sleep(2 * time.Second)

	fmt.Println("[*] GET /head (after)")
	headAfter, _ := httpJSON("GET", node+"/head", nil)
	fmt.Println(string(headAfter))

	fmt.Println("[*] GET /balance/:rid")
	bal, _ := httpJSON("GET", node+"/balance/"+rid, nil)
	fmt.Println(string(bal))

	fmt.Println("[*] Done")
}
