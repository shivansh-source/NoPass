package gateway

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/shivansh-source/nopass/internal/orchestrator"
	"github.com/shivansh-source/nopass/internal/sandbox"
	"github.com/shivansh-source/nopass/internal/types"
)

type Handler struct {
	RiskClient *RiskClient
	LLMRunner  *orchestrator.LLMRunner
}

func NewHandler(riskClient *RiskClient, llmRunner *orchestrator.LLMRunner) *Handler {
	return &Handler{
		RiskClient: riskClient,
		LLMRunner:  llmRunner,
	}
}

func (h *Handler) ChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// 1) Risk scoring
	riskResp, err := h.RiskClient.ScorePrompt(ctx, req.Message, req.UserID, req.SessionID)
	if err != nil {
		log.Printf("risk scoring error: %v", err)
		http.Error(w, "internal error (risk scoring)", http.StatusInternalServerError)
		return
	}

	// 2) Decide fast vs slow path
	path := decidePath(riskResp)

	// 3) Build Semantic Sandbox prompt
	sbInput := sandbox.SandboxInput{
		UserMessage: req.Message,
		Risk:        riskResp,
		External:    nil, // we'll add external content later
		UserID:      req.UserID,
		SessionID:   req.SessionID,
	}
	sbOutput := sandbox.BuildPrompt(sbInput)

	// 4) Run inside Docker sandbox (LLM System Sandbox)
	answer, err := h.LLMRunner.RunInSandbox(ctx, sbOutput.SystemPrompt, sbOutput.UserContent)
	if err != nil {
		log.Printf("LLM sandbox error (path=%s): %v", path, err)
		http.Error(w, "internal error (llm sandbox)", http.StatusInternalServerError)
		return
	}

	resp := types.ChatResponse{
		Answer:    answer,
		RiskLevel: riskResp.RiskLevel,
		Path:      path,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode response error: %v", err)
	}
}

// decidePath implements fast vs slow path logic based on risk metadata.
func decidePath(risk *types.RiskResponse) string {
	// default path
	path := "fast"

	// Escalate to slow path if:
	//   - risk is HIGH
	//   - OR self_check_required is true
	if risk.RiskLevel == "HIGH" || risk.SelfCheckRequired {
		path = "slow"
	}

	return path
}

// stubLLMCall simulates calling the LLM.
// Later this will:
//   - spin up Docker sandbox
//   - run the model
//   - integrate Output Safety
func (h *Handler) stubLLMCall(
	_ context.Context,
	systemPrompt, userContent, path string,
) string {
	return "[NoPass " + path + " path demo]\n\n" +
		"--- SYSTEM PROMPT ---\n" + systemPrompt + "\n\n" +
		"--- USER CONTENT ---\n" + userContent
}
