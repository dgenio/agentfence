package demo

import (
	"fmt"
	"io"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
)

func Run(out io.Writer) error {
	p, err := policy.ParsePolicy([]byte(policy.StarterPolicyYAML))
	if err != nil {
		return err
	}
	eng, err := engine.New(p)
	if err != nil {
		return err
	}
	aw := audit.NewWriter(out)

	calls := []policy.ToolCall{
		{ID: "call_001", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "README.md"}},
		{ID: "call_002", Tool: "filesystem.write", Arguments: map[string]interface{}{"path": ".env", "content": "OPENAI_API_KEY=sk-demo-secret"}},
		{ID: "call_003", Tool: "github.create_issue", Arguments: map[string]interface{}{"repo": "dgenio/agentfence", "title": "Demo issue", "body": "Created by an agent"}},
		{ID: "call_004", Tool: "github.delete_repo", Arguments: map[string]interface{}{"repo": "dgenio/agentfence"}},
	}

	fmt.Fprintln(out, "AgentFence demo:")
	for _, call := range calls {
		res, event := eng.Evaluate(call)
		fmt.Fprintf(out, "%s %s -> %s (%s)\n", call.ID, call.Tool, res.Decision, res.Reason)
		if err := aw.Write(event); err != nil {
			return err
		}
	}
	return nil
}
