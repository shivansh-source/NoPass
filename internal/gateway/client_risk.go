package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shivansh-source/nopass/internal/types"
)

type RiskClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewRiskClient(baseURL string) *RiskClient {
	return &RiskClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

func (c *RiskClient) ScorePrompt(ctx context.Context, prompt, userID, sessionID string) (*types.RiskResponse, error) {
	reqBody := types.RiskRequest{
		Prompt: prompt,
		Metadata: map[string]string{
			"user_id":    userID,
			"session_id": sessionID,
		},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal risk request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/risk-score", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create risk request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call risk service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("risk service returned status %d", resp.StatusCode)
	}

	var riskResp types.RiskResponse
	if err := json.NewDecoder(resp.Body).Decode(&riskResp); err != nil {
		return nil, fmt.Errorf("decode risk response: %w", err)
	}

	return &riskResp, nil
}
