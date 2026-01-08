package hysteria2

import (
	"strconv"
	"strings"

	"github.com/XrayR-project/XrayR/api"
)

// refreshPortHopRules is a small helper that acquires reloadMu and delegates to
// updatePortHopRulesLocked so that callers which are not already holding the
// lock (for example Start/Close) can safely refresh iptables rules.
func (h *Hysteria2Service) refreshPortHopRules() {
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	h.updatePortHopRulesLocked()
}

// updatePortHopRulesLocked recomputes and applies the iptables rules used for
// Hysteria2 port hopping based on the current h.nodeInfo. It must be called
// with reloadMu held.
func (h *Hysteria2Service) updatePortHopRulesLocked() {
	// First remove previously installed rules, if any.
	if len(h.portHopRules) > 0 {
		deletePortHopIptablesRules(h.portHopRules, h.logger)
		h.portHopRules = nil
	}

	// Then compute the desired rules from the latest node info.
	rules := buildPortHopRulesFromNode(h.nodeInfo)
	if len(rules) == 0 {
		return
	}

	applyPortHopIptablesRules(rules, h.logger)
	h.portHopRules = rules
}

// buildPortHopRulesFromNode turns the Hysteria2 port hopping configuration in
// api.NodeInfo into a concrete list of portHopRule structures that can be
// translated to iptables commands.
func buildPortHopRulesFromNode(nodeInfo *api.NodeInfo) []portHopRule {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.Hysteria2Config == nil {
		return nil
	}
	hy := nodeInfo.Hysteria2Config
	if !hy.PortHopEnabled || hy.PortHopPorts == "" {
		return nil
	}
	if nodeInfo.Port == 0 || nodeInfo.Port > 65535 {
		return nil
	}

	return buildPortHopRules(uint16(nodeInfo.Port), hy.PortHopPorts)
}

// buildPortHopRules parses a ports expression like "30000-50000,60000" and
// produces the minimal set of REDIRECT rules needed to emulate the behavior
// described in the user's requirement:
//
//   - For each port range listed in portExpr, all ports in that range are
//     redirected to basePort, *except* basePort itself.
//
//   - The final iptables commands are equivalent to manually running, e.g.:
//
//     iptables -t nat -A PREROUTING -p udp --dport 30001:50000 -j REDIRECT --to-port 30000
//
//     when basePort = 30000 and the expression is "30000-50000".
func buildPortHopRules(basePort uint16, portsExpr string) []portHopRule {
	if portsExpr == "" {
		return nil
	}

	split := func(r rune) bool {
		return r == ',' || r == '\uff0c' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	parts := strings.FieldsFunc(portsExpr, split)
	if len(parts) == 0 {
		return nil
	}

	bp := int(basePort)
	var rules []portHopRule
	for _, part := range parts {
		seg := strings.TrimSpace(part)
		if seg == "" {
			continue
		}

		var start, end int
		if dash := strings.Index(seg, "-"); dash >= 0 {
			left := strings.TrimSpace(seg[:dash])
			right := strings.TrimSpace(seg[dash+1:])
			s, err1 := strconv.Atoi(left)
			e, err2 := strconv.Atoi(right)
			if err1 != nil || err2 != nil {
				continue
			}
			start, end = s, e
		} else {
			p, err := strconv.Atoi(seg)
			if err != nil {
				continue
			}
			start, end = p, p
		}

		// Validate and normalize range.
		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			continue
		}
		if start > end {
			start, end = end, start
		}

		// If basePort lies within the configured segment, split into at most two
		// ranges so that we do NOT create a rule that explicitly mentions
		// --dport basePort, matching the user's example 30001-50000 -> 30000.
		if bp >= start && bp <= end {
			if bp > start {
				rules = append(rules, portHopRule{
					FromPortStart: uint16(start),
					FromPortEnd:   uint16(bp - 1),
					ToPort:        basePort,
				})
			}
			if bp < end {
				rules = append(rules, portHopRule{
					FromPortStart: uint16(bp + 1),
					FromPortEnd:   uint16(end),
					ToPort:        basePort,
				})
			}
			continue
		}

		// Segment does not contain basePort; redirect the whole segment.
		rules = append(rules, portHopRule{
			FromPortStart: uint16(start),
			FromPortEnd:   uint16(end),
			ToPort:        basePort,
		})
	}

	return rules
}
