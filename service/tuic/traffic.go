package tuic

import (
	"net"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/serverstatus"
)

func (s *TuicService) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	authUsers := make([]option.TUICUser, 0, len(*userInfo))
	newRateLimiters := make(map[string]*rate.Limiter)

	var nodeLimit uint64
	if s.nodeInfo != nil {
		nodeLimit = s.nodeInfo.SpeedLimit
	}

	for _, u := range *userInfo {
		// TUIC uses UUID as the primary authentication key
		key := u.UUID
		if key == "" {
			continue
		}

		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			if old, ok := s.rateLimiters[key]; ok && old != nil {
				old.SetLimit(rate.Limit(limit))
				old.SetBurst(int(limit))
				limiter = old
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		if _, ok := newUsers[key]; !ok {
			newUsers[key] = rec
		}
		if limiter != nil {
			newRateLimiters[key] = limiter
		}
		if _, ok := s.traffic[key]; !ok {
			s.traffic[key] = &userTraffic{}
		}

		// TUIC user with UUID and password (using Passwd as password)
		password := u.Passwd
		if password == "" {
			password = u.UUID
		}
		authUsers = append(authUsers, option.TUICUser{
			Name:     u.UUID,
			UUID:     u.UUID,
			Password: password,
		})
	}

	s.users = newUsers
	s.authUsers = authUsers
	s.rateLimiters = newRateLimiters

	// Log user sync result
	if s.logger != nil {
		s.logger.Infof("TUIC user sync complete: %d auth users configured", len(authUsers))
	}

	for uuid := range s.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.onlineIPs, uuid)
		}
	}
	// Clean ipLastActive records for removed users
	for uuid := range s.ipLastActive {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.ipLastActive, uuid)
		}
	}
}

func (s *TuicService) addTraffic(uuid string, up, down int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.traffic[uuid]
	if !ok {
		t = &userTraffic{}
		s.traffic[uuid] = t
	}
	t.Upload += up
	t.Download += down

	// Note: We don't update onlineIPs here because we don't have the IP address.
	// The IP is updated in Read/Write methods via updateOnlineIP().
}

func (s *TuicService) allowConnection(uuid, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[uuid]
	if !ok {
		return false
	}

	host := ip
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" {
		host = "unknown"
	}

	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}

	// Initialize ipLastActive map for this user if not exists
	activeMap, ok := s.ipLastActive[uuid]
	if !ok {
		activeMap = make(map[string]time.Time)
		s.ipLastActive[uuid] = activeMap
	}

	if _, exists := ips[host]; !exists {
		if user.DeviceLimit > 0 && len(ips) >= user.DeviceLimit {
			s.logger.WithFields(log.Fields{
				"uid":         user.UID,
				"deviceLimit": user.DeviceLimit,
				"remote":      ip,
			}).Warn("TUIC user exceeded device limit")
			return false
		}
		ips[host] = struct{}{}
	}

	// Update last active time for this IP
	activeMap[host] = time.Now()

	return true
}

// updateOnlineIP re-adds an IP to the onlineIPs map and updates its last active time.
// This is called on every traffic event to ensure active connections are tracked
// even after collectUsage() clears the maps (similar to traditional Xray protocols).
func (s *TuicService) updateOnlineIP(uuid string, addr net.Addr) {
	if addr == nil {
		return
	}

	remote := addr.String()
	host := remote
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-add IP to onlineIPs (in case it was cleared by collectUsage)
	if ipSet, exists := s.onlineIPs[uuid]; exists {
		ipSet[host] = struct{}{}
	} else {
		s.onlineIPs[uuid] = map[string]struct{}{host: {}}
	}

	// Update last active time
	if activeMap, exists := s.ipLastActive[uuid]; exists {
		activeMap[host] = time.Now()
	} else {
		s.ipLastActive[uuid] = map[string]time.Time{host: time.Now()}
	}
}

// updateOnlineIPSimple re-adds an IP (already parsed) to the onlineIPs map.
// This is used for UDP connections where the host is already extracted.
func (s *TuicService) updateOnlineIPSimple(uuid, host string) {
	if host == "" || uuid == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-add IP to onlineIPs (in case it was cleared by collectUsage)
	if ipSet, exists := s.onlineIPs[uuid]; exists {
		ipSet[host] = struct{}{}
	} else {
		s.onlineIPs[uuid] = map[string]struct{}{host: {}}
	}

	// Update last active time
	if activeMap, exists := s.ipLastActive[uuid]; exists {
		activeMap[host] = time.Now()
	} else {
		s.ipLastActive[uuid] = map[string]time.Time{host: time.Now()}
	}
}

func (s *TuicService) collectUsage() ([]api.UserTraffic, []api.OnlineUser, map[string]userTraffic) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := make(map[string]userTraffic)
	var uts []api.UserTraffic
	for uuid, t := range s.traffic {
		user, ok := s.users[uuid]
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
		t.Upload = 0
		t.Download = 0
	}

	// Collect online users before clearing
	// This mimics the behavior of traditional Xray protocols (VMess/VLESS/Trojan)
	var online []api.OnlineUser
	for uuid, ipSet := range s.onlineIPs {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			online = append(online, api.OnlineUser{UID: user.UID, IP: ip})
		}
	}

	// Clear online IPs and last active tracking after collection
	// This prevents zombie connections from accumulating over time
	// Similar to limiter.GetOnlineDevice() which calls inboundInfo.UserOnlineIP.Delete(email)
	// Only IPs that are actively used in the next reporting cycle will be tracked again
	s.onlineIPs = make(map[string]map[string]struct{})
	s.ipLastActive = make(map[string]map[string]time.Time)

	return uts, online, snapshot
}

func (s *TuicService) restoreTraffic(snapshot map[string]userTraffic) {
	if len(snapshot) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for uuid, snap := range snapshot {
		counter, ok := s.traffic[uuid]
		if !ok || counter == nil {
			counter = &userTraffic{}
			s.traffic[uuid] = counter
		}
		counter.Upload += snap.Upload
		counter.Download += snap.Download
	}
}

func (s *TuicService) userMonitor() error {
	if time.Since(s.startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		s.logger.Print(err)
	} else {
		if err = s.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			s.logger.Print(err)
		}
	}

	usersChanged := true
	newUserInfo, err := s.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
		} else {
			s.logger.Print(err)
			return nil
		}
	}
	if usersChanged {
		s.syncUsers(newUserInfo)
	}

	// Check Rule
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				s.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := s.rules.UpdateRule(s.tag, *ruleList); err != nil {
				s.logger.Print(err)
			}
		}
	}

	userTraffic, onlineUsers, snapshot := s.collectUsage()
	if len(userTraffic) > 0 && !s.config.DisableUploadTraffic {
		if err = s.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			s.logger.Print(err)
			// Restore counters so traffic is not lost and can be retried.
			s.restoreTraffic(snapshot)
		}
	}
	if len(onlineUsers) > 0 {
		if err = s.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			s.logger.Print(err)
		}
	}

	// Report Illegal user
	if s.rules != nil {
		if detectResult, err := s.rules.GetDetectResult(s.tag); err != nil {
			s.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = s.apiClient.ReportIllegal(detectResult); err != nil {
				s.logger.Print(err)
			} else {
				s.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

// nodeMonitor watches for TUIC node configuration changes from the panel
// (port, TLS/SNI, TUIC-specific options, etc.) and hot-reloads the sing-box
// instance when a change is detected.
func (s *TuicService) nodeMonitor() error {
	if time.Since(s.startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			return nil
		}
		s.logger.Print(err)
		return nil
	}

	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		if s.logger != nil {
			if nodeInfo == nil {
				s.logger.Warn("TUIC node monitor: unexpected node info: <nil>")
			} else {
				s.logger.Warnf("TUIC node monitor: unexpected node info: type=%s id=%d", nodeInfo.NodeType, nodeInfo.NodeID)
			}
		}
		return nil
	}

	// Some panels update node-related metadata frequently without changing the
	// actual TUIC configuration, which may cause the ETag to change on every
	// poll. Guard against unnecessary hot-reloads by comparing the new NodeInfo
	// with the current in-memory value, similar to controller.nodeInfoMonitor.
	if s.nodeInfo != nil && reflect.DeepEqual(s.nodeInfo, nodeInfo) {
		return nil
	}

	if err := s.reloadNode(nodeInfo); err != nil {
		s.logger.Printf("TUIC node reload failed: %v", err)
	}

	return nil
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
