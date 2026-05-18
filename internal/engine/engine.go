package engine

import (
	"fmt"
	"path"
	"path/filepath"
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

	// Normalize backslashes to forward slashes for consistent handling.
	normalized := strings.ReplaceAll(pathArg, "\\", "/")

	// Detect UNC paths (\\server\share → //server/share after normalization).
	if isUNCPath(normalized) {
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg)
	}

	// Detect Windows drive-letter absolute paths (C:/...).
	if isWindowsAbsPath(normalized) {
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg)
	}

	// Clean with filepath then convert back to forward slashes for glob matching.
	cleaned := filepath.ToSlash(filepath.Clean(normalized))

	// filepath.IsAbs covers Windows drive-letter and UNC paths; the additional
	// HasPrefix check covers Unix-style absolute paths on Windows hosts.
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "/") {
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return true, fmt.Sprintf("path %q escapes the project root", pathArg)
	}

	for _, deny := range paths.Deny {
		if matchesGlob(deny, cleaned) {
			return true, fmt.Sprintf("path %q denied by pattern %q", pathArg, deny)
		}
	}

	if len(paths.Allow) > 0 {
		for _, allow := range paths.Allow {
			if matchesGlob(allow, cleaned) {
				return false, ""
			}
		}
		return true, fmt.Sprintf("path %q not in allowed paths", pathArg)
	}
	return false, ""
}

// isUNCPath reports whether p (backslashes already converted to forward slashes)
// is a UNC path such as //server/share.
func isUNCPath(p string) bool {
	return strings.HasPrefix(p, "//")
}

// isWindowsAbsPath reports whether p (backslashes already converted to forward
// slashes) is a Windows drive-letter absolute path such as C:/ or C:.
func isWindowsAbsPath(p string) bool {
	return len(p) >= 2 && p[1] == ':' && (len(p) == 2 || p[2] == '/')
}

func matchesGlob(pattern, value string) bool {
	// "./" and "." mean "any path within the project root".
	// Callers must validate that value is a safe relative path before calling.
	if pattern == "./" || pattern == "." {
		return true
	}
	normPattern := normalizePath(pattern)
	normValue := normalizePath(value)

	if ok, _ := path.Match(normPattern, normValue); ok {
		return true
	}

	regexPattern := "^" + regexp.QuoteMeta(normPattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*\*/`, "(.*/)?")
	regexPattern = strings.ReplaceAll(regexPattern, `\*\*`, ".*")
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, "[^/]*")
	re := regexp.MustCompile(regexPattern)
	return re.MatchString(normValue)
}

func normalizePath(p string) string {
	n := strings.TrimPrefix(filepath.ToSlash(p), "./")
	if n == "" {
		return "."
	}
	return n
}
