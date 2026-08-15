package mcp

import "testing"

func TestRenameDoesNotChangeJSONRPCServerErrorCodes(t *testing.T) {
	got := []int{
		ErrorCodeBlockedByPolicy,
		ErrorCodeUpstreamUnavailable,
		ErrorCodeProxyError,
		ErrorCodeBatchNotGated,
		ErrorCodeRequestRejected,
	}
	want := []int{-32001, -32002, -32003, -32004, -32005}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("server error code[%d]=%d, want %d; branding must not change wire codes", i, got[i], want[i])
		}
	}
}
