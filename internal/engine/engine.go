package engine

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/redact"
	"github.com/dgenio/agentfence/internal/taint"
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
	result := e.evaluateDecisionCore(call, nil)
	redacted := e.redactor.RedactArguments(call.Arguments)
	event := audit.NewEvent(call, result, redacted, e.policy.Audit.IncludeRedactedArguments)
	if rule, found, _ := e.lookupRule(call.Tool); found {
		if summary := e.summarizeMemoryWrite(rule, call); summary != nil {
			event.MemoryWrite = summary
		}
	}
	return result, event
}

// Session is a stateful evaluator that layers session-scoped taint tracking on
// top of the engine's stateless evaluation. It is created with Engine.NewSession
// and is the evaluation entry point for the MCP proxy, where tool outputs are
// observable. A Session is safe for concurrent use: the proxy observes results
// on one goroutine while evaluating calls on another.
//
// When taint tracking is disabled in policy, a Session behaves exactly like the
// stateless Engine.
type Session struct {
	eng     *Engine
	tracker *taint.Tracker
	mode    string
	enabled bool
}

// NewSession returns a Session bound to this engine. Taint tracking is enabled
// only when the policy's taint.enabled is true.
func (e *Engine) NewSession() *Session {
	tc := e.policy.Taint
	s := &Session{eng: e, enabled: tc.Enabled, mode: tc.OnTaintedArgument}
	if tc.Enabled {
		s.tracker = taint.NewTracker(tc.MinLength)
	}
	return s
}

// TaintEnabled reports whether this session tracks taint. Callers (the proxy)
// use it to skip parsing tool results when there is nothing to track.
func (s *Session) TaintEnabled() bool { return s.enabled }

// Evaluate evaluates call against the policy and then, if taint tracking is on,
// escalates the decision when an argument is derived from previously observed
// untrusted tool output. The returned audit event reflects the final decision.
func (s *Session) Evaluate(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	res, event := s.eng.Evaluate(call)
	if s.tracker == nil {
		return res, event
	}
	if hit, ok := s.tracker.Check(call.Arguments); ok {
		res, event = applyTaintEscalation(res, event, hit, s.mode)
	}
	return res, event
}

// ObserveResult records text returned by sourceTool as untrusted, so a later
// call argument derived from it can be flagged. A no-op when taint is disabled.
func (s *Session) ObserveResult(sourceTool, text string) {
	if s.tracker != nil {
		s.tracker.Observe(sourceTool, text)
	}
}

// applyTaintEscalation adjusts a decision when an argument is tainted. The taint
// source (the upstream tool and the offending field) is recorded in the reason
// so it surfaces in the audit record. "deny" mode forces a deny; the default
// "escalate" mode lifts an allow to ask and leaves ask/deny untouched.
func applyTaintEscalation(res policy.EvaluationResult, event audit.Event, hit taint.Hit, mode string) (policy.EvaluationResult, audit.Event) {
	detail := fmt.Sprintf("argument %q derived from untrusted output of %q (matched %q)", hit.Field, hit.SourceTool, hit.Fragment)
	switch mode {
	case policy.TaintDeny:
		if res.Decision != policy.DecisionDeny {
			res.Decision = policy.DecisionDeny
			res.Reason = "tainted_argument: " + detail + "; denied by taint policy"
			res.ReasonCode = policy.ReasonCodeTaintDenied
		}
	default: // escalate
		if res.Decision == policy.DecisionAllow {
			res.Decision = policy.DecisionAsk
			res.Reason = "tainted_argument: " + detail + "; escalated allow→ask"
			res.ReasonCode = policy.ReasonCodeTaintEscalated
		}
	}
	event.Decision = res.Decision
	event.Reason = res.Reason
	event.ReasonCode = res.ReasonCode
	return res, event
}

// TraceEvaluate evaluates a tool call and returns a human-readable trace of each
// evaluation step alongside the decision. Intended for the explain command.
func (e *Engine) TraceEvaluate(call policy.ToolCall) (policy.EvaluationResult, []string) {
	var trace []string
	result := e.evaluateDecisionCore(call, &trace)
	return result, trace
}

func (e *Engine) evaluateDecisionCore(call policy.ToolCall, trace *[]string) policy.EvaluationResult {
	rule, found, matchedKey := e.lookupRule(call.Tool)
	if !found {
		appendTrace(trace, fmt.Sprintf("no rule found for %q; applying default decision %q", call.Tool, e.policy.Defaults.Decision))
		return policy.EvaluationResult{
			Decision:   e.policy.Defaults.Decision,
			Reason:     fmt.Sprintf("no rule for %s; using default decision", call.Tool),
			ReasonCode: policy.ReasonCodeDefaultDecision,
		}
	}

	appendTrace(trace, fmt.Sprintf("matched rule %q (decision: %s)", matchedKey, rule.Decision))

	if deny, reason, code := evaluatePathConstraints(rule, call, trace); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason, ReasonCode: code}
	}
	if deny, reason, code := evaluateArgConstraints(rule, call, trace); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason, ReasonCode: code}
	}
	if deny, reason, code := evaluateURLConstraints(rule, call, trace); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason, ReasonCode: code}
	}
	if deny, reason, code := evaluateCommandConstraints(rule, call, trace); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason, ReasonCode: code}
	}
	if deny, reason, code := evaluateMemoryWriteConstraints(rule, call, e.redactor, trace); deny {
		return policy.EvaluationResult{Decision: policy.DecisionDeny, Reason: reason, ReasonCode: code}
	}

	appendTrace(trace, fmt.Sprintf("all constraints passed; decision: %s", rule.Decision))
	return policy.EvaluationResult{
		Decision:   rule.Decision,
		Reason:     e.reasonForMatch(call.Tool, matchedKey),
		ReasonCode: policy.ReasonCodeRuleMatch,
	}
}

func (e *Engine) reasonForMatch(toolName, matchedKey string) string {
	if matchedKey == toolName {
		return fmt.Sprintf("tool %s matched explicit policy rule", toolName)
	}
	if _, ok := e.policy.Groups[matchedKey]; ok {
		return fmt.Sprintf("tool %s matched group rule %q", toolName, matchedKey)
	}
	return fmt.Sprintf("tool %s matched wildcard rule %q", toolName, matchedKey)
}

// lookupRule finds the first applicable rule for toolName using this precedence:
//  1. Exact match against Tools keys.
//  2. Group match: tool matches a member pattern of a named group that has a Tools entry.
//     Groups are checked in alphabetical order for determinism.
//  3. Wildcard/glob match against remaining Tools keys, checked in alphabetical order.
//
// TODO(perf): precompute sorted group names, group set, and pattern keys in New()
// to eliminate per-call allocations when processing large batches.
func (e *Engine) lookupRule(toolName string) (policy.Rule, bool, string) {
	// 1. Exact match.
	if r, ok := e.policy.Tools[toolName]; ok {
		return r, true, toolName
	}

	// 2. Group match: sorted group names for determinism.
	groupNames := make([]string, 0, len(e.policy.Groups))
	for gn := range e.policy.Groups {
		groupNames = append(groupNames, gn)
	}
	sort.Strings(groupNames)
	for _, groupName := range groupNames {
		for _, member := range e.policy.Groups[groupName] {
			if matchesGlob(member, toolName) {
				if r, ok := e.policy.Tools[groupName]; ok {
					return r, true, groupName
				}
				break // group exists but has no rule; keep searching
			}
		}
	}

	// 3. Wildcard/glob match on non-exact, non-group tool keys, sorted for determinism.
	groupSet := make(map[string]bool, len(e.policy.Groups))
	for gn := range e.policy.Groups {
		groupSet[gn] = true
	}
	patternKeys := make([]string, 0, len(e.policy.Tools))
	for k := range e.policy.Tools {
		if k != toolName && !groupSet[k] {
			patternKeys = append(patternKeys, k)
		}
	}
	sort.Strings(patternKeys)
	for _, pattern := range patternKeys {
		if matchesGlob(pattern, toolName) {
			return e.policy.Tools[pattern], true, pattern
		}
	}

	return policy.Rule{}, false, ""
}

// appendTrace appends msg to the trace slice when trace is non-nil.
func appendTrace(trace *[]string, msg string) {
	if trace != nil {
		*trace = append(*trace, msg)
	}
}

func evaluatePathConstraints(rule policy.Rule, call policy.ToolCall, trace *[]string) (bool, string, policy.ReasonCode) {
	paths := rule.Constraints.Paths
	pathArg, ok := call.Arguments["path"].(string)
	hasPathConstraints := len(paths.Allow) > 0 || len(paths.Deny) > 0
	if !ok || pathArg == "" {
		if !hasPathConstraints {
			return false, "", policy.ReasonCodeUnspecified
		}
		appendTrace(trace, "path constraint: missing path argument → deny")
		return true, "missing required path argument for constrained tool", policy.ReasonCodePathMissing
	}

	deny, reason, cleaned := evaluatePathSafety(pathArg, trace)
	if deny {
		return true, reason, policy.ReasonCodePathUnsafe
	}
	if !hasPathConstraints {
		return false, "", policy.ReasonCodeUnspecified
	}

	appendTrace(trace, fmt.Sprintf("checking path constraints for %q (normalized: %q)", pathArg, cleaned))

	for _, deny := range paths.Deny {
		if matchesGlob(deny, cleaned) {
			appendTrace(trace, fmt.Sprintf("path %q denied by pattern %q", pathArg, deny))
			return true, fmt.Sprintf("path %q denied by pattern %q", pathArg, deny), policy.ReasonCodePathDenied
		}
	}

	if len(paths.Allow) > 0 {
		for _, allow := range paths.Allow {
			if matchesGlob(allow, cleaned) {
				appendTrace(trace, fmt.Sprintf("path %q matched allow pattern %q", pathArg, allow))
				return false, "", policy.ReasonCodeUnspecified
			}
		}
		appendTrace(trace, fmt.Sprintf("path %q not matched by any allow pattern → deny", pathArg))
		return true, fmt.Sprintf("path %q not in allowed paths", pathArg), policy.ReasonCodePathNotAllowed
	}
	return false, "", policy.ReasonCodeUnspecified
}

func evaluatePathSafety(pathArg string, trace *[]string) (bool, string, string) {
	// Normalize backslashes to forward slashes for consistent handling.
	normalized := strings.ReplaceAll(pathArg, "\\", "/")

	// Detect UNC paths (\\server\share → //server/share after normalization).
	if isUNCPath(normalized) {
		appendTrace(trace, fmt.Sprintf("path %q is UNC/absolute → deny", pathArg))
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg), ""
	}

	// Detect Windows drive-qualified paths (C:/..., C:, and drive-relative
	// C:foo). All carry a drive letter that is never a safe project-relative
	// path on any host.
	if isWindowsDrivePath(normalized) {
		appendTrace(trace, fmt.Sprintf("path %q is Windows drive-qualified → deny", pathArg))
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg), ""
	}

	// Clean with filepath then convert back to forward slashes for glob matching.
	cleaned := filepath.ToSlash(filepath.Clean(normalized))

	// filepath.IsAbs covers Windows drive-letter and UNC paths; the additional
	// HasPrefix check covers Unix-style absolute paths on Windows hosts.
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "/") {
		appendTrace(trace, fmt.Sprintf("path %q is absolute → deny", pathArg))
		return true, fmt.Sprintf("path %q is absolute; only relative paths are allowed", pathArg), ""
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		appendTrace(trace, fmt.Sprintf("path %q escapes project root → deny", pathArg))
		return true, fmt.Sprintf("path %q escapes the project root", pathArg), ""
	}

	return false, "", cleaned
}

// evaluateArgConstraints checks constraints.args: per-field allow/deny glob lists.
// Non-string values are converted to string via fmt.Sprintf("%v", v) before matching.
// A missing constrained field is denied.
func evaluateArgConstraints(rule policy.Rule, call policy.ToolCall, trace *[]string) (bool, string, policy.ReasonCode) {
	if len(rule.Constraints.Args) == 0 {
		return false, "", policy.ReasonCodeUnspecified
	}
	// Sort field names for deterministic evaluation order.
	fields := make([]string, 0, len(rule.Constraints.Args))
	for f := range rule.Constraints.Args {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	for _, field := range fields {
		constraint := rule.Constraints.Args[field]
		v, ok := call.Arguments[field]
		if !ok || v == nil {
			appendTrace(trace, fmt.Sprintf("arg constraint %q: argument missing → deny", field))
			return true, fmt.Sprintf("missing required argument %q for constrained tool", field), policy.ReasonCodeArgMissing
		}

		var strVal string
		if s, isStr := v.(string); isStr {
			strVal = s
		} else {
			strVal = fmt.Sprintf("%v", v)
		}

		appendTrace(trace, fmt.Sprintf("checking arg constraint %q against value %q", field, strVal))

		for _, deny := range constraint.Deny {
			if matchesGlob(deny, strVal) {
				appendTrace(trace, fmt.Sprintf("arg %q value %q denied by pattern %q", field, strVal, deny))
				return true, fmt.Sprintf("argument %q value %q denied by pattern %q", field, strVal, deny), policy.ReasonCodeArgDenied
			}
		}

		if len(constraint.Allow) > 0 {
			matched := false
			for _, allow := range constraint.Allow {
				if matchesGlob(allow, strVal) {
					appendTrace(trace, fmt.Sprintf("arg %q value %q matched allow pattern %q", field, strVal, allow))
					matched = true
					break
				}
			}
			if !matched {
				appendTrace(trace, fmt.Sprintf("arg %q value %q not matched by any allow pattern → deny", field, strVal))
				return true, fmt.Sprintf("argument %q value %q not in allowed values", field, strVal), policy.ReasonCodeArgNotAllowed
			}
		}
	}
	return false, "", policy.ReasonCodeUnspecified
}

// evaluateURLConstraints checks constraints.urls against the url argument.
// file:// scheme and bare IP hostnames are always denied regardless of the allow list.
func evaluateURLConstraints(rule policy.Rule, call policy.ToolCall, trace *[]string) (bool, string, policy.ReasonCode) {
	urls := rule.Constraints.URLs
	if len(urls.Allow) == 0 && len(urls.Deny) == 0 {
		return false, "", policy.ReasonCodeUnspecified
	}

	raw, ok := call.Arguments["url"].(string)
	if !ok || raw == "" {
		appendTrace(trace, "url constraint: missing url argument → deny")
		return true, "missing required url argument for constrained tool", policy.ReasonCodeURLMissing
	}

	appendTrace(trace, fmt.Sprintf("checking url constraints for %q", raw))

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		appendTrace(trace, fmt.Sprintf("url %q is not a valid URL → deny", raw))
		return true, fmt.Sprintf("url %q is not a valid URL", raw), policy.ReasonCodeURLInvalid
	}

	// Always deny file:// scheme.
	if parsed.Scheme == "file" {
		appendTrace(trace, fmt.Sprintf("url %q uses file:// scheme → deny (always denied)", raw))
		return true, fmt.Sprintf("url %q uses file:// scheme which is always denied", raw), policy.ReasonCodeURLFileScheme
	}

	// Always deny bare IP hostnames.
	host := parsed.Hostname()
	if net.ParseIP(host) != nil {
		appendTrace(trace, fmt.Sprintf("url %q has bare IP host %q → deny (always denied)", raw, host))
		return true, fmt.Sprintf("url %q uses a bare IP address which is always denied", raw), policy.ReasonCodeURLBareIP
	}

	for _, deny := range urls.Deny {
		if matchesGlob(deny, raw) {
			appendTrace(trace, fmt.Sprintf("url %q denied by pattern %q", raw, deny))
			return true, fmt.Sprintf("url %q denied by pattern %q", raw, deny), policy.ReasonCodeURLDenied
		}
	}

	if len(urls.Allow) > 0 {
		for _, allow := range urls.Allow {
			if matchesGlob(allow, raw) {
				appendTrace(trace, fmt.Sprintf("url %q matched allow pattern %q", raw, allow))
				return false, "", policy.ReasonCodeUnspecified
			}
		}
		appendTrace(trace, fmt.Sprintf("url %q not matched by any allow pattern → deny", raw))
		return true, fmt.Sprintf("url %q not in allowed URLs", raw), policy.ReasonCodeURLNotAllowed
	}
	return false, "", policy.ReasonCodeUnspecified
}

// evaluateCommandConstraints checks constraints.command for shell/terminal tools.
// deny_patterns are matched against the full command string; allow_executables checks
// only the first token. Deny takes precedence over allow.
//
// WARNING: This is a best-effort guardrail only. Shell metacharacters (|, ;, &&, $())
// can bypass these checks. Do not rely on this as a security sandbox.
func evaluateCommandConstraints(rule policy.Rule, call policy.ToolCall, trace *[]string) (bool, string, policy.ReasonCode) {
	cmd := rule.Constraints.Command
	if len(cmd.AllowExecutables) == 0 && len(cmd.DenyPatterns) == 0 {
		return false, "", policy.ReasonCodeUnspecified
	}

	raw, ok := call.Arguments["command"].(string)
	if !ok || raw == "" {
		appendTrace(trace, "command constraint: missing command argument → deny")
		return true, "missing required command argument for constrained tool", policy.ReasonCodeCommandMissing
	}

	appendTrace(trace, fmt.Sprintf("checking command constraints for %q", raw))

	// Check deny patterns first (matched against full command string).
	for _, pattern := range cmd.DenyPatterns {
		if matchesGlob(pattern, raw) {
			appendTrace(trace, fmt.Sprintf("command %q denied by pattern %q", raw, pattern))
			return true, fmt.Sprintf("command %q denied by pattern %q", raw, pattern), policy.ReasonCodeCommandDenied
		}
	}

	// Check allow_executables against the first token.
	if len(cmd.AllowExecutables) > 0 {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			appendTrace(trace, "command is empty after splitting → deny")
			return true, "command is empty", policy.ReasonCodeCommandEmpty
		}
		executable := fields[0]
		for _, allowed := range cmd.AllowExecutables {
			if allowed == executable {
				appendTrace(trace, fmt.Sprintf("executable %q is in allow_executables list", executable))
				return false, "", policy.ReasonCodeUnspecified
			}
		}
		appendTrace(trace, fmt.Sprintf("executable %q not in allow_executables list → deny", executable))
		return true, fmt.Sprintf("executable %q is not in the allowed executables list", executable), policy.ReasonCodeCommandExecNotAllowed
	}

	return false, "", policy.ReasonCodeUnspecified
}

// isUNCPath reports whether p (backslashes already converted to forward slashes)
// is a UNC path such as //server/share.
func isUNCPath(p string) bool {
	return strings.HasPrefix(p, "//")
}

// isWindowsDrivePath reports whether p (backslashes already converted to
// forward slashes) carries a Windows drive-letter prefix. This covers the
// absolute form (C:/Windows), the bare drive root (C:), and the drive-relative
// form (C:foo, which Windows resolves against the drive's current directory).
// None of these is a safe project-relative path: on a non-Windows host
// filepath.Clean would otherwise treat "C:foo" as an ordinary relative name
// and let it through, so the check is made explicitly and host-independently.
func isWindowsDrivePath(p string) bool {
	return len(p) >= 2 && isASCIILetter(p[0]) && p[1] == ':'
}

// isASCIILetter reports whether b is an ASCII letter (A–Z or a–z).
func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
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
	// regexp.Compile (not MustCompile) so fuzz-discovered or future malformed
	// patterns degrade to "no match" instead of panicking the whole evaluator.
	// In practice this branch is unreachable: regexPattern is built from
	// regexp.QuoteMeta plus a fixed set of glob→regex substitutions, all of
	// which are valid. If it ever were reachable, "no match" is the safe
	// default — the engine falls back to the policy's default decision (deny
	// by default), so a non-compiling pattern never silently grants access.
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	return re.MatchString(normValue)
}

func normalizePath(p string) string {
	n := strings.TrimPrefix(filepath.ToSlash(p), "./")
	if n == "" {
		return "."
	}
	return n
}

// evaluateMemoryWriteConstraints enforces a rule's memory_write constraints.
// A rule opts in by setting any of max_scope, max_sensitivity, max_bytes, or
// payload_fields. The call must carry a non-empty payload in one of the
// configured payload fields (default: value, content); a missing payload is
// denied. Scope defaults to "session". Sensitivity is the higher of any
// explicit "sensitivity" argument and the redactor's classification of the
// payload (any pattern match → high).
func evaluateMemoryWriteConstraints(rule policy.Rule, call policy.ToolCall, redactor *redact.Redactor, trace *[]string) (bool, string, policy.ReasonCode) {
	mw := rule.Constraints.MemoryWrite
	if !mw.IsSet() {
		return false, "", policy.ReasonCodeUnspecified
	}

	appendTrace(trace, "checking memory_write constraints")

	callScope := memoryWriteScope(call)
	if mw.MaxScope != "" {
		callRank := policy.MemoryScopeRank(callScope)
		if callRank < 0 {
			appendTrace(trace, fmt.Sprintf("memory_write: unknown scope %q → deny", callScope))
			return true, fmt.Sprintf("memory write scope %q is not recognised", callScope), policy.ReasonCodeMemoryScopeInvalid
		}
		maxRank := policy.MemoryScopeRank(mw.MaxScope)
		if callRank > maxRank {
			appendTrace(trace, fmt.Sprintf("memory_write: scope %q exceeds max_scope %q → deny", callScope, mw.MaxScope))
			return true, fmt.Sprintf("memory write scope %q exceeds max allowed %q", callScope, mw.MaxScope), policy.ReasonCodeMemoryScopeExceeded
		}
	}

	payload, field := memoryWritePayload(rule, call)
	if payload == "" {
		fields := memoryWritePayloadFields(rule)
		appendTrace(trace, fmt.Sprintf("memory_write: no payload found in fields %v → deny", fields))
		return true, fmt.Sprintf("memory write requires a non-empty payload in one of %v", fields), policy.ReasonCodeMemoryPayloadMissing
	}

	if mw.MaxBytes > 0 && len(payload) > mw.MaxBytes {
		appendTrace(trace, fmt.Sprintf("memory_write: payload %d bytes exceeds max_bytes %d → deny", len(payload), mw.MaxBytes))
		return true, fmt.Sprintf("memory write payload %d bytes exceeds max allowed %d", len(payload), mw.MaxBytes), policy.ReasonCodeMemorySizeExceeded
	}

	if mw.MaxSensitivity != "" {
		if explicit, present, valid := memoryWriteExplicitSensitivity(call.Arguments); present && !valid {
			appendTrace(trace, fmt.Sprintf("memory_write: unknown sensitivity %q → deny", explicit))
			return true, fmt.Sprintf("memory write sensitivity %q is not recognised", explicit), policy.ReasonCodeMemorySensitivityInvalid
		}
		sensitivity := classifyMemoryWriteSensitivity(payload, call.Arguments, redactor)
		callRank := policy.MemorySensitivityRank(sensitivity)
		if callRank < 0 {
			appendTrace(trace, fmt.Sprintf("memory_write: unknown sensitivity %q → deny", sensitivity))
			return true, fmt.Sprintf("memory write sensitivity %q is not recognised", sensitivity), policy.ReasonCodeMemorySensitivityInvalid
		}
		maxRank := policy.MemorySensitivityRank(mw.MaxSensitivity)
		if callRank > maxRank {
			appendTrace(trace, fmt.Sprintf("memory_write: sensitivity %s exceeds max_sensitivity %s → deny", sensitivity, mw.MaxSensitivity))
			return true, fmt.Sprintf("memory write sensitivity %q exceeds max allowed %q", sensitivity, mw.MaxSensitivity), policy.ReasonCodeMemorySensitivityExceeded
		}
	}

	appendTrace(trace, fmt.Sprintf("memory_write: scope=%s field=%s size=%d → all constraints passed", callScope, field, len(payload)))
	return false, "", policy.ReasonCodeUnspecified
}

// summarizeMemoryWrite builds the audit MemoryWriteSummary for a rule that
// opted in to memory-write evaluation. Returns nil when the rule did not
// opt in. The summary intentionally never carries the raw payload.
func (e *Engine) summarizeMemoryWrite(rule policy.Rule, call policy.ToolCall) *audit.MemoryWriteSummary {
	mw := rule.Constraints.MemoryWrite
	if !mw.IsSet() {
		return nil
	}
	payload, field := memoryWritePayload(rule, call)
	scope := memoryWriteScope(call)
	sensitivity := classifyMemoryWriteSensitivity(payload, call.Arguments, e.redactor)

	summary := &audit.MemoryWriteSummary{
		Scope:       scope,
		Sensitivity: sensitivity,
		Field:       field,
		SizeBytes:   len(payload),
	}
	if payload != "" {
		summary.ContentFingerprint = redact.FingerprintPayload(payload)
		summary.PatternsMatched = e.redactor.MatchedConfiguredPatternNames(payload)
	}
	return summary
}

func memoryWriteScope(call policy.ToolCall) string {
	if s, ok := call.Arguments["scope"].(string); ok && s != "" {
		return s
	}
	return "session"
}

func memoryWritePayloadFields(rule policy.Rule) []string {
	if len(rule.Constraints.MemoryWrite.PayloadFields) > 0 {
		return rule.Constraints.MemoryWrite.PayloadFields
	}
	return policy.DefaultPayloadFields
}

func memoryWritePayload(rule policy.Rule, call policy.ToolCall) (string, string) {
	for _, f := range memoryWritePayloadFields(rule) {
		v, ok := call.Arguments[f]
		if !ok {
			continue
		}
		s, isStr := v.(string)
		if !isStr || s == "" {
			continue
		}
		return s, f
	}
	return "", ""
}

func classifyMemoryWriteSensitivity(payload string, args map[string]interface{}, redactor *redact.Redactor) string {
	explicit := ""
	if s, present, valid := memoryWriteExplicitSensitivity(args); present && valid {
		explicit = s
	}
	detected := "low"
	if redactor != nil && redactor.MatchesConfiguredPattern(payload) {
		detected = "high"
	}
	if policy.MemorySensitivityRank(explicit) > policy.MemorySensitivityRank(detected) {
		return explicit
	}
	return detected
}

func memoryWriteExplicitSensitivity(args map[string]interface{}) (string, bool, bool) {
	raw, ok := args["sensitivity"]
	if !ok {
		return "", false, true
	}
	s, ok := raw.(string)
	if !ok || policy.MemorySensitivityRank(s) < 0 {
		return fmt.Sprint(raw), true, false
	}
	return s, true, true
}
