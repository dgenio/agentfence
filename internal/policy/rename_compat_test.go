package policy

import "testing"

func TestRenameDoesNotChangePublishedReasonCodes(t *testing.T) {
	cases := []struct {
		got  ReasonCode
		want string
	}{
		{ReasonCodeUnspecified, ""},
		{ReasonCodeRuleMatch, "rule_match"},
		{ReasonCodeDefaultDecision, "default_decision"},
		{ReasonCodePathMissing, "path_missing"},
		{ReasonCodePathUnsafe, "path_unsafe"},
		{ReasonCodePathDenied, "path_denied"},
		{ReasonCodePathNotAllowed, "path_not_allowed"},
		{ReasonCodeArgMissing, "arg_missing"},
		{ReasonCodeArgDenied, "arg_denied"},
		{ReasonCodeArgNotAllowed, "arg_not_allowed"},
		{ReasonCodeURLMissing, "url_missing"},
		{ReasonCodeURLInvalid, "url_invalid"},
		{ReasonCodeURLFileScheme, "url_file_scheme"},
		{ReasonCodeURLBareIP, "url_bare_ip"},
		{ReasonCodeURLDenied, "url_denied"},
		{ReasonCodeURLNotAllowed, "url_not_allowed"},
		{ReasonCodeCommandMissing, "command_missing"},
		{ReasonCodeCommandEmpty, "command_empty"},
		{ReasonCodeCommandDenied, "command_denied"},
		{ReasonCodeCommandExecNotAllowed, "command_executable_not_allowed"},
		{ReasonCodeMemoryScopeInvalid, "memory_scope_invalid"},
		{ReasonCodeMemoryScopeExceeded, "memory_scope_exceeded"},
		{ReasonCodeMemoryPayloadMissing, "memory_payload_missing"},
		{ReasonCodeMemorySizeExceeded, "memory_size_exceeded"},
		{ReasonCodeMemorySensitivityInvalid, "memory_sensitivity_invalid"},
		{ReasonCodeMemorySensitivityExceeded, "memory_sensitivity_exceeded"},
		{ReasonCodeTaintEscalated, "taint_escalated"},
		{ReasonCodeTaintDenied, "taint_denied"},
		{ReasonCodeApprovalApproved, "approval_approved"},
		{ReasonCodeApprovalDenied, "approval_denied"},
		{ReasonCodeApprovalTimeout, "approval_timeout"},
		{ReasonCodeApprovalCancelled, "approval_cancelled"},
		{ReasonCodeApprovalIOError, "approval_io_error"},
		{ReasonCodeNonInteractive, "non_interactive_denied"},
		{ReasonCodeParseError, "parse_error"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Fatalf("reason code=%q, want %q; branding must not change machine values", tc.got, tc.want)
		}
	}
}
