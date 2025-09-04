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

const defaultNode = "http://127.0.0.1:8080"

// порядок канонического сообщения на сервере:
// amount, from, nonce, public_key, to
type canonMsg struct {
	Amount    uint64 `json:"amount"`
	From      string `json:"from"`
	Nonce     uint64 `json:"nonce"`
	PublicKey string `json:"public_key"`
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

func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }

func httpJSON(method, url string, body any) ([]byte, int) {
	var rd io.Reader
	if body != nil {
		b := must(json.Marshal(body))
		rd = bytes.NewReader(b)
	}
	req := must(http.NewRequest(method, url, rd))
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp := must(client.Do(req))
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode
}

func httpSimple(method, url string) ([]byte, int) {
	req := must(http.NewRequest(method, url, nil))
	client := &http.Client{Timeout: 10 * time.Second}
	resp := must(client.Do(req))
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode
}

func main() {
	node := os.Getenv("LRB_NODE")
	if node == "" { node = defaultNode }
	fmt.Println("[*] Node:", node)

	// Генерим A и B (ключи, RID)
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	ridA := base58.Encode(pubA)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	ridB := base58.Encode(pubB)

	fmt.Println("[*] RID_A:", ridA)
	fmt.Println("[*] RID_B:", ridB)

	// 0) Краник для A (DEV режим должен быть включён: LRB_DEV=1 в сервисе)
	faucetURL := fmt.Sprintf("%s/faucet/%s/%d", node, ridA, 1_000_000)
	if b, code := httpSimple("POST", faucetURL); code == 200 {
		fmt.Println("[*] faucet ok:", string(b))
	} else {
		fmt.Println("[!] faucet failed code:", code, "body:", string(b))
	}

	// 1) Head/balances до
	fmt.Println("[*] GET /head (before)")
	if b, _ := httpSimple("GET", node+"/head"); len(b) > 0 { fmt.Println(string(b)) }

	fmt.Println("[*] GET balances (before)")
	if b, _ := httpSimple("GET", node+"/balance/"+ridA); len(b) > 0 { fmt.Println("A:", string(b)) }
	if b, _ := httpSimple("GET", node+"/balance/"+ridB); len(b) > 0 { fmt.Println("B:", string(b)) }

	// 2) Канон по серверу
	amount := uint64(777)
	nonce  := uint64(1)
	canon := canonMsg{
		Amount:    amount,
		From:      ridA,
		Nonce:     nonce,
		PublicKey: base64.StdEncoding.EncodeToString(pubA),
		To:        ridB,
	}
	canonBytes := must(json.Marshal(canon))
	sig := ed25519.Sign(privA, canonBytes)

	req := submitTx{
		From:         ridA,
		To:           ridB,
		Amount:       amount,
		Nonce:        nonce,
		PublicKeyB58: base58.Encode(pubA),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}

	fmt.Println("[*] POST /submit_tx  A->B 777")
	if resp, code := httpJSON("POST", node+"/submit_tx", req); true {
		fmt.Println("status:", code, "body:", string(resp))
	}

	// 3) Ждём слот продюсера
	time.Sleep(1500 * time.Millisecond)

	// 4) Head/balances после
	fmt.Println("[*] GET /head (after)")
	if b, _ := httpSimple("GET", node+"/head"); len(b) > 0 { fmt.Println(string(b)) }

	fmt.Println("[*] GET balances (after)")
	if b, _ := httpSimple("GET", node+"/balance/"+ridA); len(b) > 0 { fmt.Println("A:", string(b)) }
	if b, _ := httpSimple("GET", node+"/balance/"+ridB); len(b) > 0 { fmt.Println("B:", string(b)) }

	fmt.Println("[*] Done")
}
