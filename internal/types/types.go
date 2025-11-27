package types

type ExternalData struct {
	ID          string `json:"id"`
	Source      string `json:"source"` // e.g. "kb:payments", "web:https://..."
	Type        string `json:"type"`   // e.g. "document", "web_page"
	Content     string `json:"content"`
	IsDangerous bool   `json:"-"` // Internal flag
}

type ChatRequest struct {
	UserID       string         `json:"user_id"`
	SessionID    string         `json:"session_id"`
	Message      string         `json:"message"`
	ExternalData []ExternalData `json:"external_data,omitempty"`
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

// ----- Output Safety ----- //

type OutputSafetyRequest struct {
	UserPrompt  string   `json:"user_prompt"`
	DraftAnswer string   `json:"draft_answer"`
	RiskLevel   string   `json:"risk_level"`
	Flags       []string `json:"flags"`
	Mode        string   `json:"mode"` // "fast" or "slow"
}

type OutputSafetyResponse struct {
	FinalAnswer string   `json:"final_answer"`
	WasModified bool     `json:"was_modified"`
	ReasonFlags []string `json:"reason_flags"`
}
