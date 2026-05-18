package engine

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/redact"
)

type Engine struct {
	policy   policy.Policy
	redactor *redact.Redactor
}

func New(p policy.Policy) (*Engine, error) {
	r, err := redact.New(p.Redaction)
	if err != nil {
		return nil, err
	}
	return &Engine{policy: p, redactor: r}, nil
}

func (e *Engine) Evaluate(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	result := e.evaluateDecision(call)
	redacted := e.redactor.RedactArguments(call.Arguments)
	event := audit.NewEvent(call, result, redacted, e.policy.Audit.IncludeRedactedArguments)
	return result, event
}

func (e *Engine) evaluateDecision(call policy.ToolCall) policy.EvaluationResult {
	rule, ok := e.policy.Tools[call.Tool]
	if !ok {
		return policy.EvaluationResult{
			Decision: e.policy.Defaults.Decision,
			Reason:   fmt.Sprintf("no rule for %s; using default decision", call.Tool),
		}
	}

	if deny, reason := evaluatePathConstraints(rule, call); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason}
	}

	return policy.EvaluationResult{
		Decision: rule.Decision,
		Reason:   fmt.Sprintf("tool %s matched explicit policy rule", call.Tool),
	}
}

func evaluatePathConstraints(rule policy.Rule, call policy.ToolCall) (bool, string) {
	paths := rule.Constraints.Paths
	if len(paths.Allow) == 0 && len(paths.Deny) == 0 {
		return false, ""
	}
	pathArg, ok := call.Arguments["path"].(string)
	if !ok || pathArg == "" {
		return true, "missing required path argument for constrained tool"
	}

	for _, deny := range paths.Deny {
		if matchesGlob(deny, pathArg) {
			return true, fmt.Sprintf("path %q denied by pattern %q", pathArg, deny)
		}
	}

	if len(paths.Allow) > 0 {
		for _, allow := range paths.Allow {
			if matchesGlob(allow, pathArg) {
				return false, ""
			}
		}
		return true, fmt.Sprintf("path %q not in allowed paths", pathArg)
	}
	return false, ""
}

func matchesGlob(pattern, value string) bool {
	if pattern == "./" || pattern == "." {
		return true
	}
	normPattern := normalizePath(pattern)
	normValue := normalizePath(value)

	if ok, _ := path.Match(normPattern, normValue); ok {
		return true
	}

	regexPattern := "^" + regexp.QuoteMeta(normPattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*\*`, ".*")
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, "[^/]*")
	re := regexp.MustCompile(regexPattern)
	return re.MatchString(normValue)
}

func normalizePath(p string) string {
	n := strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./")
	if n == "" {
		return "."
	}
	return n
}
