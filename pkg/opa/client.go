package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	URL  string
	HTTP *http.Client
}

func NewClient(url string) *Client {
	if url == "" {
		url = "http://localhost:8181/v1/data/wardseal/authz"
	}
	return &Client{
		URL:  url,
		HTTP: &http.Client{Timeout: 2 * time.Second},
	}
}

type Input struct {
	User   string                 `json:"user"`
	Action string                 `json:"action"`
	Object string                 `json:"object"`
	Claims map[string]interface{} `json:"claims,omitempty"`
}

type Request struct {
	Input Input `json:"input"`
}

type Response struct {
	Result struct {
		Allow bool `json:"allow"`
	} `json:"result"`
}

func (c *Client) Check(ctx context.Context, input Input) (bool, error) {
	reqBody, err := json.Marshal(Request{Input: input})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("OPA check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned status: %d", resp.StatusCode)
	}

	var res Response
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, err
	}

	return res.Result.Allow, nil
}
