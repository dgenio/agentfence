package main

import (
	"fmt"
	"strings"
)

func renderMarkdown(report evidenceReport) string {
	var b strings.Builder
	b.WriteString("# VeriCordon authorization evidence report\n\n")
	b.WriteString("> Preview generated from AgentFence local evidence. This is scoped engineering evidence, not a security certification or compliance attestation.\n\n")
	if report.Context != "" {
		fmt.Fprintf(&b, "**Context:** `%s`\n\n", markdownCode(report.Context))
	}
	b.WriteString("## Evidence summary\n\n")
	fmt.Fprintf(&b, "- Mediated decisions supplied: **%d** (allow %d · deny %d · ask %d)\n", report.Summary.Decisions, report.Summary.Allow, report.Summary.Deny, report.Summary.Ask)
	fmt.Fprintf(&b, "- Audit events inspected for binding evidence: **%d**; both action + policy digests present: **%d**\n", report.Summary.AuditEvents, report.Summary.BoundAuditEvents)
	if report.Summary.PolicyTests > 0 {
		fmt.Fprintf(&b, "- Policy fixtures: **%d** (passed %d · failed %d)\n", report.Summary.PolicyTests, report.Summary.PolicyTestsPassed, report.Summary.PolicyTestsFailed)
	}

	b.WriteString("\n## Evidence checks\n\n")
	b.WriteString("| Check | Status | What the supplied evidence says | Boundary |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, check := range report.Checks {
		fmt.Fprintf(&b, "| `%s` | **%s** | %s | %s |\n", markdownCell(check.ID), markdownCell(check.Status), markdownCell(check.Summary), markdownCell(check.Limitation))
	}

	b.WriteString("\n## Evidence index\n\n")
	for _, name := range report.EvidenceIndex {
		fmt.Fprintf(&b, "- `%s`\n", markdownCode(name))
	}

	b.WriteString("\n## Limitations / non-claims\n\n")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	b.WriteString("\nNo missing, partial, or unevaluated evidence should be interpreted as safety.\n")
	return b.String()
}

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func markdownCode(s string) string {
	return strings.ReplaceAll(s, "`", "'")
}
