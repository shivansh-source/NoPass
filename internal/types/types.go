package types

type ChatRequest struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
}

type ChatResponse struct {
	Answer    string `json:"answer"`
	RiskLevel string `json:"risk_level"`
	Path      string `json:"path"` // "fast" or "slow"
}

// ----- Types used to talk to Python risk service ----- //

type RiskRequest struct {
	Prompt   string            `json:"prompt"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type RiskResponse struct {
	SanitizedPrompt   string   `json:"sanitized_prompt"`
	RiskLevel         string   `json:"risk_level"`
	Flags             []string `json:"flags"`
	SelfCheckRequired bool     `json:"self_check_required"`
}
