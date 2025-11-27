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

type OutputSafetyClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewOutputSafetyClient(baseURL string) *OutputSafetyClient {
	return &OutputSafetyClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Mode is "fast" or "slow"
func (c *OutputSafetyClient) Review(
	ctx context.Context,
	userPrompt, draftAnswer, riskLevel string,
	flags []string,
	mode string,
) (*types.OutputSafetyResponse, error) {
	reqBody := types.OutputSafetyRequest{
		UserPrompt:  userPrompt,
		DraftAnswer: draftAnswer,
		RiskLevel:   riskLevel,
		Flags:       flags,
		Mode:        mode,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal output safety request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/output-safety", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create output safety request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call output safety service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("output safety service returned status %d", resp.StatusCode)
	}

	var out types.OutputSafetyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode output safety response: %w", err)
	}

	return &out, nil
}
