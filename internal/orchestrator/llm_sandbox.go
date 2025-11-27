package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// SandboxConfig allows basic configuration if needed later.
type SandboxConfig struct {
	ImageName string
	Timeout   time.Duration
}

// LLMRunner orchestrates LLM calls inside Docker.
type LLMRunner struct {
	cfg SandboxConfig
}

// NewLLMRunner creates a new LLMRunner with a default config.
func NewLLMRunner() *LLMRunner {
	return &LLMRunner{
		cfg: SandboxConfig{
			ImageName: "nopass-llm-sandbox:latest",
			Timeout:   15 * time.Second,
		},
	}
}

// RunInSandbox:
//   - Creates a temp directory
//   - Writes system/user prompts to files
//   - Runs Docker with:
//     --network none
//     -v tempDir:/app/input:ro
//   - Returns stdout as the "LLM answer".
func (r *LLMRunner) RunInSandbox(ctx context.Context, systemPrompt, userContent string) (string, error) {
	// Create temp dir
	tempDir, err := os.MkdirTemp("", "nopass-llm-input-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	// Clean up after
	defer os.RemoveAll(tempDir)

	// Write files
	if err := ioutil.WriteFile(filepath.Join(tempDir, "system.txt"), []byte(systemPrompt), 0o600); err != nil {
		return "", fmt.Errorf("write system prompt: %w", err)
	}
	if err := ioutil.WriteFile(filepath.Join(tempDir, "user.txt"), []byte(userContent), 0o600); err != nil {
		return "", fmt.Errorf("write user content: %w", err)
	}

	// On Windows, Docker Desktop expects paths like C:\path or /c/path.
	// We'll pass the raw path; if needed, you can adjust this to your local Docker setup.
	vol := fmt.Sprintf("%s:/app/input:ro", r.normalizePathForDocker(tempDir))

	// Prepare Docker command
	cmdCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(
		cmdCtx,
		"docker", "run",
		"--rm",
		"--network", "none",
		"-v", vol,
		r.cfg.ImageName,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Distinguish between timeout and other errors.
		if cmdCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("docker run timed out: %w", cmdCtx.Err())
		}
		return "", fmt.Errorf("docker run error: %v, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// normalizePathForDocker attempts to adjust host paths for Docker on different OSes.
func (r *LLMRunner) normalizePathForDocker(p string) string {
	// Basic implementation:
	// - On Unix, we can pass as-is.
	// - On Windows, Docker often supports the same path, or you might need to convert.
	if runtime.GOOS == "windows" {
		// Example: convert "C:\Users\me\AppData\Local\Temp\..." to "C:/Users/..."
		p = strings.ReplaceAll(p, `\`, `/`)
	}
	return p
}
