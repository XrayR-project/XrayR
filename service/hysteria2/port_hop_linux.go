//go:build linux
// +build linux

package hysteria2

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// applyPortHopIptablesRules installs iptables NAT PREROUTING rules for the
// given port ranges so that traffic to the external ports is redirected to the
// underlying Hysteria2 server port. The generated commands are intentionally
// equivalent to the manual examples provided by the user, e.g.:
//
//   iptables -t nat -A PREROUTING -p udp --dport 30001:50000 -j REDIRECT --to-port 30000
func applyPortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	for _, r := range rules {
		args := []string{"-t", "nat", "-A", "PREROUTING", "-p", "udp"}
		if r.FromPortStart == r.FromPortEnd {
			args = append(args, "--dport", fmt.Sprintf("%d", r.FromPortStart))
		} else {
			args = append(args, "--dport", fmt.Sprintf("%d:%d", r.FromPortStart, r.FromPortEnd))
		}
		args = append(args, "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.ToPort))

		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Errorf("Hysteria2 port hop: failed to add iptables rule (%v): %v, output: %s", r, err, string(out))
		} else {
			logger.Debugf("Hysteria2 port hop: added iptables rule (%v)", r)
		}
	}
}

// deletePortHopIptablesRules removes previously installed iptables rules. Each
// rule must match exactly the arguments used when it was added.
func deletePortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	for _, r := range rules {
		args := []string{"-t", "nat", "-D", "PREROUTING", "-p", "udp"}
		if r.FromPortStart == r.FromPortEnd {
			args = append(args, "--dport", fmt.Sprintf("%d", r.FromPortStart))
		} else {
			args = append(args, "--dport", fmt.Sprintf("%d:%d", r.FromPortStart, r.FromPortEnd))
		}
		args = append(args, "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.ToPort))

		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// If the rule no longer exists we just log at debug level instead of
			// failing hard, to keep behavior close to manually running iptables -D.
			logger.Debugf("Hysteria2 port hop: failed to delete iptables rule (%v): %v, output: %s", r, err, string(out))
		} else {
			logger.Debugf("Hysteria2 port hop: deleted iptables rule (%v)", r)
		}
	}
}
