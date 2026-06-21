package policy

// ReasonCode is a stable, machine-readable classification of why a decision was
// reached. It travels alongside the human-readable Reason string: the Reason is
// for operators reading a log, while the ReasonCode lets downstream tools
// (audit summarize, metrics counters, exporters) group decisions without
// string-matching prose that may change wording over time.
//
// Codes are stable identifiers. Adding a new decision path means adding a new
// code here; existing code values must not change once shipped.
type ReasonCode string

const (
	// ReasonCodeUnspecified is the zero value, used when no code was set. It
	// should not appear on a fully evaluated decision; its presence indicates a
	// decision path that predates the taxonomy.
	ReasonCodeUnspecified ReasonCode = ""

	// ReasonCodeRuleMatch is set when a tool matched a policy rule (explicit,
	// group, or wildcard) and all of the rule's constraints passed. The
	// decision is the rule's own decision (allow/deny/ask).
	ReasonCodeRuleMatch ReasonCode = "rule_match"

	// ReasonCodeDefaultDecision is set when no rule matched the tool and the
	// policy's default decision was applied.
	ReasonCodeDefaultDecision ReasonCode = "default_decision"

	// Path-constraint denials.
	ReasonCodePathMissing    ReasonCode = "path_missing"
	ReasonCodePathUnsafe     ReasonCode = "path_unsafe"
	ReasonCodePathDenied     ReasonCode = "path_denied"
	ReasonCodePathNotAllowed ReasonCode = "path_not_allowed"

	// Argument-constraint denials.
	ReasonCodeArgMissing    ReasonCode = "arg_missing"
	ReasonCodeArgDenied     ReasonCode = "arg_denied"
	ReasonCodeArgNotAllowed ReasonCode = "arg_not_allowed"

	// URL-constraint denials.
	ReasonCodeURLMissing    ReasonCode = "url_missing"
	ReasonCodeURLInvalid    ReasonCode = "url_invalid"
	ReasonCodeURLFileScheme ReasonCode = "url_file_scheme"
	ReasonCodeURLBareIP     ReasonCode = "url_bare_ip"
	ReasonCodeURLDenied     ReasonCode = "url_denied"
	ReasonCodeURLNotAllowed ReasonCode = "url_not_allowed"

	// Command-constraint denials.
	ReasonCodeCommandMissing        ReasonCode = "command_missing"
	ReasonCodeCommandEmpty          ReasonCode = "command_empty"
	ReasonCodeCommandDenied         ReasonCode = "command_denied"
	ReasonCodeCommandExecNotAllowed ReasonCode = "command_executable_not_allowed"

	// Memory-write-constraint denials.
	ReasonCodeMemoryScopeInvalid        ReasonCode = "memory_scope_invalid"
	ReasonCodeMemoryScopeExceeded       ReasonCode = "memory_scope_exceeded"
	ReasonCodeMemoryPayloadMissing      ReasonCode = "memory_payload_missing"
	ReasonCodeMemorySizeExceeded        ReasonCode = "memory_size_exceeded"
	ReasonCodeMemorySensitivityInvalid  ReasonCode = "memory_sensitivity_invalid"
	ReasonCodeMemorySensitivityExceeded ReasonCode = "memory_sensitivity_exceeded"

	// Taint escalations (set by the session evaluator).
	ReasonCodeTaintEscalated ReasonCode = "taint_escalated"
	ReasonCodeTaintDenied    ReasonCode = "taint_denied"

	// Approval outcomes (set when an ask decision is resolved by an approver).
	ReasonCodeApprovalApproved  ReasonCode = "approval_approved"
	ReasonCodeApprovalDenied    ReasonCode = "approval_denied"
	ReasonCodeApprovalTimeout   ReasonCode = "approval_timeout"
	ReasonCodeApprovalCancelled ReasonCode = "approval_cancelled"
	ReasonCodeApprovalIOError   ReasonCode = "approval_io_error"
	ReasonCodeNonInteractive    ReasonCode = "non_interactive_denied"

	// ReasonCodeParseError is set on the synthetic deny event produced for an
	// input line that could not be parsed as a tool call.
	ReasonCodeParseError ReasonCode = "parse_error"
)
