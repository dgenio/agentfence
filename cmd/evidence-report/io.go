package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func readDecisions(path string) ([]decisionSummary, error) {
	var decisions []decisionSummary
	if err := readJSON(path, &decisions); err != nil {
		return nil, fmt.Errorf("decisions: %w", err)
	}
	return decisions, nil
}

func readJSON(path string, dst any) error {
	// The report generator is a local CLI: every input path is explicitly
	// supplied by the operator/action invoking it, matching AgentFence's policy
	// and key-file path trust boundary.
	data, err := os.ReadFile(path) // #nosec G304 -- local operator-supplied evidence path
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}

func auditBindingCounts(path string) (int, int, error) {
	if path == "" {
		return 0, 0, nil
	}
	// The path is a local operator/action-supplied evidence input. It is never
	// derived from a remote request or untrusted audit payload.
	file, err := os.Open(path) // #nosec G304 -- local operator-supplied evidence path
	if err != nil {
		return 0, 0, fmt.Errorf("audit: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	total := 0
	bound := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return 0, 0, fmt.Errorf("audit: invalid JSONL event %d: %w", total+1, err)
		}
		total++
		if event.ActionDigest != "" && event.PolicyDigest != "" {
			bound++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("audit: %w", err)
	}
	return total, bound, nil
}

func writeJSON(path string, report evidenceReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func writeMarkdown(path string, report evidenceReport) error {
	if err := os.WriteFile(path, []byte(renderMarkdown(report)), 0o600); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}
