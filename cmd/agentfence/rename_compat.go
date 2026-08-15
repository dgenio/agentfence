package main

import (
	"errors"
	"fmt"
)

const (
	preferredProxyAuthEnv = "VERICORDON_PROXY_AUTH_TOKEN"
	legacyProxyAuthEnv    = "AGENTFENCE_PROXY_AUTH_TOKEN"
)

// envLookup matches os.LookupEnv while keeping rename compatibility logic easy
// to unit-test without mutating process-global environment state.
type envLookup func(string) (string, bool)

// proxyAuthResolution is the result of resolving the explicit flag and the two
// bounded-compatibility environment variables used during the AgentFence ->
// VeriCordon rename.
type proxyAuthResolution struct {
	Token   string
	Warning string
}

// resolveProxyAuthToken applies the approved #242 migration contract.
//
// Security-sensitive precedence is deliberately explicit:
//   - a non-empty --auth-token value wins over both environment variables;
//   - the preferred VERICORDON_* variable is accepted directly;
//   - the legacy AGENTFENCE_* variable is accepted with a deprecation warning;
//   - equal legacy/new values are accepted with a migration warning;
//   - conflicting non-empty legacy/new values fail closed instead of silently
//     selecting a credential.
//
// Empty environment values are treated as absent. Token bytes are otherwise
// preserved exactly; no trimming or normalization is performed on credentials.
func resolveProxyAuthToken(flagValue string, lookup envLookup) (proxyAuthResolution, error) {
	if flagValue != "" {
		return proxyAuthResolution{Token: flagValue}, nil
	}
	if lookup == nil {
		return proxyAuthResolution{}, errors.New("proxy auth environment lookup is unavailable")
	}

	preferred, preferredSet := lookup(preferredProxyAuthEnv)
	legacy, legacySet := lookup(legacyProxyAuthEnv)
	preferredSet = preferredSet && preferred != ""
	legacySet = legacySet && legacy != ""

	switch {
	case preferredSet && legacySet && preferred != legacy:
		return proxyAuthResolution{}, fmt.Errorf(
			"conflicting %s and %s values; refusing to choose a proxy auth credential",
			preferredProxyAuthEnv,
			legacyProxyAuthEnv,
		)
	case preferredSet && legacySet:
		return proxyAuthResolution{
			Token: preferred,
			Warning: fmt.Sprintf(
				"%s is deprecated; both proxy auth environment variables currently resolve to the same credential; remove %s",
				legacyProxyAuthEnv,
				legacyProxyAuthEnv,
			),
		}, nil
	case preferredSet:
		return proxyAuthResolution{Token: preferred}, nil
	case legacySet:
		return proxyAuthResolution{
			Token: legacy,
			Warning: fmt.Sprintf(
				"%s is deprecated; migrate to %s",
				legacyProxyAuthEnv,
				preferredProxyAuthEnv,
			),
		}, nil
	default:
		return proxyAuthResolution{}, nil
	}
}
