//go:build !linux
// +build !linux

package hysteria2

import (
	log "github.com/sirupsen/logrus"
)

// On non-Linux platforms there is no iptables binary. We simply log and skip
// installing rules so that the core Hysteria2 service can still run.

func applyPortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	if len(rules) > 0 {
		logger.Warn("Hysteria2 port hop: iptables is only supported on Linux; skipping port hop rules on this platform")
	}
}

func deletePortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	// nothing to do on non-Linux platforms
}
