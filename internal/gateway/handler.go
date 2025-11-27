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
	RiskClient         *RiskClient
	LLMRunner          *orchestrator.LLMRunner
	OutputSafetyClient *OutputSafetyClient
}

func NewHandler(
	riskClient *RiskClient,
	llmRunner *orchestrator.LLMRunner,
	outputClient *OutputSafetyClient,
) *Handler {
	return &Handler{
		RiskClient:         riskClient,
		LLMRunner:          llmRunner,
		OutputSafetyClient: outputClient,
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
	mode := path // "fast" or "slow"

	// 3) Scan External Data (Indirect Prompt Injection Defense)
	// We scan each chunk. If high risk, we mark it as dangerous.
	for i := range req.ExternalData {
		// We use the same RiskClient but maybe we want a different threshold or logic later.
		// For now, we just check the content.
		risk, err := h.RiskClient.ScorePrompt(ctx, req.ExternalData[i].Content, req.UserID, req.SessionID)
		if err != nil {
			log.Printf("error scanning external data %s: %v", req.ExternalData[i].ID, err)
			// Fail open or closed? Let's fail open but log it for now, or maybe mark dangerous?
			// Let's mark dangerous to be safe if we can't scan.
			req.ExternalData[i].IsDangerous = true
			continue
		}

		if risk.RiskLevel == "HIGH" {
			log.Printf("external data %s flagged as HIGH risk", req.ExternalData[i].ID)
			req.ExternalData[i].IsDangerous = true
		}
	}

	// 4) Build Semantic Sandbox prompt
	sbInput := sandbox.SandboxInput{
		UserMessage: req.Message,
		Risk:        riskResp,
		External:    req.ExternalData,
		UserID:      req.UserID,
		SessionID:   req.SessionID,
	}
	sbOutput := sandbox.BuildPrompt(sbInput)

	// 4) Run inside Docker sandbox (LLM System Sandbox)
	draftAnswer, err := h.LLMRunner.RunInSandbox(ctx, sbOutput.SystemPrompt, sbOutput.UserContent)
	if err != nil {
		log.Printf("LLM sandbox error (path=%s): %v", path, err)
		http.Error(w, "internal error (llm sandbox)", http.StatusInternalServerError)
		return
	}

	// 5) Output Safety Layer
	outResp, err := h.OutputSafetyClient.Review(
		ctx,
		req.Message, // original user prompt
		draftAnswer, // draft answer from LLM sandbox
		riskResp.RiskLevel,
		riskResp.Flags,
		mode,
	)
	if err != nil {
		log.Printf("output safety error (path=%s): %v", path, err)
		http.Error(w, "internal error (output safety)", http.StatusInternalServerError)
		return
	}

	resp := types.ChatResponse{
		Answer:    outResp.FinalAnswer,
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
