package hysteria2

import (
	"context"
	"reflect"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/serverstatus"
)

// hyTrafficLogger implements server.TrafficLogger and records user traffic
// into the service's in-memory counters.
type hyTrafficLogger struct {
	svc *Hysteria2Service
}

func (t *hyTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	if id == "" {
		return true
	}

	var limiter *rate.Limiter

	t.svc.mu.Lock()

	// If this connection has been marked as violating an audit rule, signal
	// the core to disconnect it by returning false.
	if t.svc.blockedIDs != nil {
		if blocked := t.svc.blockedIDs[id]; blocked {
			delete(t.svc.blockedIDs, id)
			if t.svc.logger != nil {
				t.svc.logger.WithField("id", id).Warn("Hysteria2 closing connection due to audit rule")
			}
			t.svc.mu.Unlock()
			return false
		}
	}

	if _, ok := t.svc.users[id]; !ok {
		t.svc.mu.Unlock()
		return true
	}
	counter, ok := t.svc.traffic[id]
	if !ok {
		counter = &userTraffic{}
		t.svc.traffic[id] = counter
	}
	counter.Upload += int64(tx)
	counter.Download += int64(rx)

	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[id]
	}

	t.svc.mu.Unlock()

	if limiter != nil {
		total := int(tx + rx)
		if total > 0 {
			_ = limiter.WaitN(context.Background(), total)
		}
	}

	return true
}

func (t *hyTrafficLogger) LogOnlineState(id string, online bool) {
	// Online state is tracked via Authenticator using the onlineIPs map.
}

func (t *hyTrafficLogger) TraceStream(stream server.HyStream, stats *server.StreamStats) {}

func (t *hyTrafficLogger) UntraceStream(stream server.HyStream) {}

// syncUsers syncs the internal user map from the panel provided user list.
func (h *Hysteria2Service) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	newRateLimiters := make(map[string]*rate.Limiter)

	var nodeLimit uint64
	if h.nodeInfo != nil {
		nodeLimit = h.nodeInfo.SpeedLimit
	}

	for _, u := range *userInfo {
		// Primary auth key is UUID; fallback to Passwd for panels that
		// use the password field for Hysteria2 authentication.
		keys := []string{u.UUID, u.Passwd}
		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			// Try to reuse an existing limiter if present.
			for _, k := range keys {
				if k == "" {
					continue
				}
				if old, ok := h.rateLimiters[k]; ok && old != nil {
					old.SetLimit(rate.Limit(limit))
					old.SetBurst(int(limit))
					limiter = old
					break
				}
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		for _, k := range keys {
			if k == "" {
				continue
			}
			if _, ok := newUsers[k]; !ok {
				newUsers[k] = rec
			}
			if limiter != nil {
				newRateLimiters[k] = limiter
			}
			if _, ok := h.traffic[k]; !ok {
				h.traffic[k] = &userTraffic{}
			}
		}
	}

	h.users = newUsers
	h.rateLimiters = newRateLimiters

	// Clean online IP records for removed users
	for uuid := range h.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(h.onlineIPs, uuid)
		}
	}
	// Clean ipLastActive records for removed users
	for uuid := range h.ipLastActive {
		if _, ok := newUsers[uuid]; !ok {
			delete(h.ipLastActive, uuid)
		}
	}
}

func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		}
		return 0
	}

	if nodeLimit > userLimit {
		return userLimit
	} else if nodeLimit < userLimit {
		return nodeLimit
	}
	return nodeLimit
}

// collectUsage builds traffic and online user reports and resets the
// corresponding in-memory counters.
//
// It returns a snapshot of the per-user traffic that was reported so that
// callers can restore the counters if reporting fails, avoiding silent
// loss of usage data.
func (h *Hysteria2Service) collectUsage() ([]api.UserTraffic, []api.OnlineUser, map[string]userTraffic) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// snapshot keeps a copy of the counters that are being reported in this
	// cycle so that userMonitor can restore them on report failure.
	snapshot := make(map[string]userTraffic)
	var uts []api.UserTraffic
	for uuid, t := range h.traffic {
		user, ok := h.users[uuid]
		if !ok {
			continue
		}
		if t.Upload == 0 && t.Download == 0 {
			continue
		}
		snapshot[uuid] = userTraffic{
			Upload:   t.Upload,
			Download: t.Download,
		}
		uts = append(uts, api.UserTraffic{
			UID:      user.UID,
			Email:    user.Email,
			Upload:   t.Upload,
			Download: t.Download,
		})
		// reset counters after taking the snapshot
		t.Upload = 0
		t.Download = 0
	}

	// Collect online users before clearing
	// This mimics the behavior of traditional Xray protocols (VMess/VLESS/Trojan)
	var onlineUsers []api.OnlineUser
	for uuid, ipSet := range h.onlineIPs {
		user, ok := h.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			onlineUsers = append(onlineUsers, api.OnlineUser{UID: user.UID, IP: ip})
		}
	}

	// Clear online IPs and last active tracking after collection
	// This prevents zombie connections from accumulating over time
	// Similar to limiter.GetOnlineDevice() which calls inboundInfo.UserOnlineIP.Delete(email)
	// Only IPs that are actively used in the next reporting cycle will be tracked again
	h.onlineIPs = make(map[string]map[string]struct{})
	h.ipLastActive = make(map[string]map[string]time.Time)

	return uts, onlineUsers, snapshot
}

// restoreTraffic merges a previously captured snapshot back into the
// in-memory counters. This is used when ReportUserTraffic fails so that
// the usage data can be retried in a later reporting cycle.
func (h *Hysteria2Service) restoreTraffic(snapshot map[string]userTraffic) {
	if len(snapshot) == 0 {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for uuid, snap := range snapshot {
		counter, ok := h.traffic[uuid]
		if !ok || counter == nil {
			counter = &userTraffic{}
			h.traffic[uuid] = counter
		}
		counter.Upload += snap.Upload
		counter.Download += snap.Download
	}
}

// userMonitor is the periodic task used by Hysteria2Service to
// - report node status
// - refresh user list
// - report user traffic and online users.
func (h *Hysteria2Service) userMonitor() error {
	// delay to start
	if time.Since(h.startAt) < time.Duration(h.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		h.logger.Print(err)
	} else {
		if err = h.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			h.logger.Print(err)
		}
	}

	// Update User
	usersChanged := true
	newUserInfo, err := h.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
		} else {
			h.logger.Print(err)
			return nil
		}
	}
	if usersChanged {
		h.syncUsers(newUserInfo)
	}

	// Check Rule
	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, err := h.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				h.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := h.rules.UpdateRule(h.tag, *ruleList); err != nil {
				h.logger.Print(err)
			}
		}
	}

	// Collect traffic & online users
	userTraffic, onlineUsers, snapshot := h.collectUsage()
	if len(userTraffic) > 0 {
		var reportErr error
		if !h.config.DisableUploadTraffic {
			reportErr = h.apiClient.ReportUserTraffic(&userTraffic)
		}
		if reportErr != nil {
			h.logger.Print(reportErr)
			// Restore counters so traffic is not lost and can be retried.
			h.restoreTraffic(snapshot)
		}
	}
	if len(onlineUsers) > 0 {
		if err = h.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			h.logger.Print(err)
		}
	}

	// Report Illegal user
	if h.rules != nil {
		if detectResult, err := h.rules.GetDetectResult(h.tag); err != nil {
			h.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = h.apiClient.ReportIllegal(detectResult); err != nil {
				h.logger.Print(err)
			} else {
				h.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

// nodeMonitor watches for node-level configuration changes from the panel
// (including port, TLS/SNI and speed limits) and hot-reloads the underlying
// Hysteria2 server when needed. This avoids having to restart the whole
// XrayR process when you edit the node on the panel.
func (h *Hysteria2Service) nodeMonitor() error {
	// delay to start, keep in sync with userMonitor behaviour
	if time.Since(h.startAt) < time.Duration(h.config.UpdatePeriodic)*time.Second {
		return nil
	}

	nodeInfo, err := h.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			return nil
		}
		h.logger.Print(err)
		return nil
	}

	if nodeInfo == nil || nodeInfo.NodeType != "Hysteria2" {
		if h.logger != nil {
			h.logger.Warnf("Hysteria2 node monitor: unexpected node info: %v", nodeInfo)
		}
		return nil
	}

	// Panels may update node metadata (such as statistics) frequently without
	// changing the actual Hysteria2 node configuration. This can cause the ETag
	// to change and GetNodeInfo to return 200 each time, leading to unnecessary
	// server restarts. Avoid that by comparing the new NodeInfo with the current
	// one and only reloading when there is a real config change.
	if h.nodeInfo != nil && reflect.DeepEqual(h.nodeInfo, nodeInfo) {
		return nil
	}

	if err := h.reloadNode(nodeInfo); err != nil {
		h.logger.Printf("Hysteria2 node reload failed: %v", err)
	}

	return nil
}
