package main

import (
	"log"
	"net/http"
	"os"

	"github.com/shivansh-source/nopass/internal/gateway"
	"github.com/shivansh-source/nopass/internal/orchestrator"
)

func main() {
	riskURL := os.Getenv("NOPASS_RISK_URL")
	if riskURL == "" {
		riskURL = "http://localhost:8001" // default for local dev
	}

	riskClient := gateway.NewRiskClient(riskURL)
	llmRunner := orchestrator.NewLLMRunner()

	handler := gateway.NewHandler(riskClient, llmRunner)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat", handler.ChatHandler)

	addr := ":8080"
	log.Printf("NoPass Gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
