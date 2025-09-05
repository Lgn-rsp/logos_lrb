package logosapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Base   string
	Admin  string
	Client *http.Client
	TO     time.Duration
}

func New(base string, admin string, timeout time.Duration) *Client {
	if timeout == 0 { timeout = 10 * time.Second }
	return &Client{
		Base:  trimSlash(base),
		Admin: admin,
		Client: &http.Client{ Timeout: timeout },
		TO: timeout,
	}
}

func trimSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' { return s[:len(s)-1] }
	return s
}

func (c *Client) req(ctx context.Context, method, path string, body io.Reader, out any, hdr map[string]string) error {
	req, _ := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	req.Header.Set("Content-Type", "application/json")
	for k,v := range hdr { req.Header.Set(k,v) }
	if c.Admin != "" { req.Header.Set("X-Admin-Key", c.Admin) }

	resp, err := c.Client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}
	if out != nil { return json.Unmarshal(b, out) }
	return nil
}

type Healthz struct { Status string `json:"status"` }
type HeadResp struct { Height uint64 `json:"height"`; Finalized bool `json:"finalized"` }
type BalanceResp struct { Rid string `json:"rid"`; Balance uint64 `json:"balance"`; Nonce uint64 `json:"nonce"` }

type TxIn struct {
	From string `json:"from"`
	To   string `json:"to"`
	Amount uint64 `json:"amount"`
	Nonce  uint64 `json:"nonce"`
	SigHex string `json:"sig_hex"`
}
type SubmitTxBatchReq struct { Txs []TxIn `json:"txs"` }
type TxResult struct { Idx int `json:"idx"`; Status string `json:"status"`; Code int `json:"code"`; Reason string `json:"reason"` }
type SubmitTxBatchResp struct { Accepted int `json:"accepted"`; Rejected int `json:"rejected"`; NewHeight uint64 `json:"new_height"`; Results []TxResult `json:"results"` }

func (c *Client) Healthz(ctx context.Context) (Healthz, error) { var h Healthz; err := c.req(ctx,"GET","/healthz",nil,&h,nil); return h,err }
func (c *Client) Head(ctx context.Context) (HeadResp, error) { var h HeadResp; err := c.req(ctx,"GET","/head",nil,&h,nil); return h,err }
func (c *Client) Balance(ctx context.Context, rid string) (BalanceResp, error) {
	var b BalanceResp; err := c.req(ctx,"GET","/balance/"+rid,nil,&b,nil); return b,err }
func (c *Client) DebugCanon(ctx context.Context, tx map[string]any) (map[string]string, error) {
	var out map[string]string
	buf, _ := json.Marshal(map[string]any{"tx":tx})
	err := c.req(ctx,"POST","/debug_canon", io.NopCloser(io.NewReader(buf)), &out, nil)
	return out, err
}
func (c *Client) SubmitBatch(ctx context.Context, req SubmitTxBatchReq) (SubmitTxBatchResp, error) {
	var out SubmitTxBatchResp
	buf, _ := json.Marshal(req)
	err := c.req(ctx,"POST","/submit_tx_batch", io.NopCloser(io.NewReader(buf)), &out, nil)
	return out, err
}
