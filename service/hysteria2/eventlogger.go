package hysteria2

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// hyEventLogger implements server.EventLogger and prints useful
// diagnostics so that connection and handshake issues can be
// investigated from XrayR's log output.
type hyEventLogger struct {
	svc *Hysteria2Service
}

func (l *hyEventLogger) logger() *log.Entry {
	if l == nil || l.svc == nil || l.svc.logger == nil {
		return log.NewEntry(log.StandardLogger())
	}
	return l.svc.logger
}

// userFields resolves the given Hysteria2 connection ID (which is the
// auth string returned by the Authenticator) to a stable, non-sensitive
// user identity such as UID / email for logging purposes.
func (l *hyEventLogger) userFields(id string) log.Fields {
	fields := log.Fields{}
	if l == nil || l.svc == nil {
		return fields
	}

	l.svc.mu.RLock()
	defer l.svc.mu.RUnlock()

	if user, ok := l.svc.users[id]; ok {
		fields["uid"] = user.UID
	}
	return fields
}

func (l *hyEventLogger) auditRequest(addr net.Addr, id, reqAddr string) {
	if l == nil || l.svc == nil || l.svc.rules == nil {
		return
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	l.svc.mu.RLock()
	user, ok := l.svc.users[id]
	l.svc.mu.RUnlock()
	if !ok || reqAddr == "" {
		return
	}

	userKey := fmt.Sprintf("%d", user.UID)
	if l.svc.rules.Detect(l.svc.tag, reqAddr, userKey, host) {
		// Mark this connection ID as blocked. The TrafficLogger will see this
		// flag and return false on the next traffic callback, which instructs
		// the Hysteria2 core to disconnect the client immediately.
		if l.svc.blockedIDs != nil {
			l.svc.mu.Lock()
			l.svc.blockedIDs[id] = true
			l.svc.mu.Unlock()
		}

		l.logger().WithFields(log.Fields{
			"remote":  host,
			"reqAddr": reqAddr,
			"uid":     user.UID,
		}).Warn("Hysteria2 audit rule hit, scheduling disconnect")
	}
}

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	fields := log.Fields{
		"remote": addr.String(),
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Info("Hysteria2 client connected")
}

func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
			host = h
		}
	}

	fields := log.Fields{
		"remote": remote,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}

	// Remove this IP from online IP tracking.
	if l != nil && l.svc != nil && id != "" && host != "" {
		l.svc.mu.Lock()
		if ipSet, ok := l.svc.onlineIPs[id]; ok {
			delete(ipSet, host)
			if len(ipSet) == 0 {
				delete(l.svc.onlineIPs, id)
			}
		}
		// Also remove from ipLastActive
		if activeMap, ok := l.svc.ipLastActive[id]; ok {
			delete(activeMap, host)
			if len(activeMap) == 0 {
				delete(l.svc.ipLastActive, id)
			}
		}
		l.svc.mu.Unlock()
	}

	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 client disconnected with error")
	} else {
		l.logger().WithFields(fields).Info("Hysteria2 client disconnected")
	}
}

func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, err := net.SplitHostPort(remote); err == nil {
			host = h
		}
	}

	var (
		user    userRecord
		ok      bool
		nodeTag string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.tag

		l.svc.mu.RLock()
		user, ok = l.svc.users[id]
		l.svc.mu.RUnlock()

		// Update last active time and re-add IP to onlineIPs
		// This ensures that active connections are tracked even after collectUsage() clears the maps
		// Similar to how traditional Xray protocols call GetUserBucket on every traffic event
		if ok && host != "" && id != "" {
			l.svc.mu.Lock()
			// Re-add IP to onlineIPs (in case it was cleared by collectUsage)
			if ipSet, exists := l.svc.onlineIPs[id]; exists {
				ipSet[host] = struct{}{}
			} else {
				l.svc.onlineIPs[id] = map[string]struct{}{host: struct{}{}}
			}
			// Update last active time
			if activeMap, exists := l.svc.ipLastActive[id]; exists {
				activeMap[host] = time.Now()
			} else {
				l.svc.ipLastActive[id] = map[string]time.Time{host: time.Now()}
			}
			l.svc.mu.Unlock()
		}
	}

	if ok {
		l.logger().Infof("from %s accepted tcp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted tcp:%s [%s]",
			remote, reqAddr, nodeTag)
	}

	l.auditRequest(addr, id, reqAddr)
}

func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	fields := log.Fields{
		"remote":  addr.String(),
		"reqAddr": reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 TCP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 TCP error")
	}
}

func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	remote := ""
	host := ""
	if addr != nil {
		remote = addr.String()
		host = remote
		if h, _, err := net.SplitHostPort(remote); err == nil {
			host = h
		}
	}

	var (
		user    userRecord
		ok      bool
		nodeTag string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.tag

		l.svc.mu.RLock()
		user, ok = l.svc.users[id]
		l.svc.mu.RUnlock()

		// Update last active time and re-add IP to onlineIPs
		// This ensures that active connections are tracked even after collectUsage() clears the maps
		// Similar to how traditional Xray protocols call GetUserBucket on every traffic event
		if ok && host != "" && id != "" {
			l.svc.mu.Lock()
			// Re-add IP to onlineIPs (in case it was cleared by collectUsage)
			if ipSet, exists := l.svc.onlineIPs[id]; exists {
				ipSet[host] = struct{}{}
			} else {
				l.svc.onlineIPs[id] = map[string]struct{}{host: {}}
			}
			// Update last active time
			if activeMap, exists := l.svc.ipLastActive[id]; exists {
				activeMap[host] = time.Now()
			} else {
				l.svc.ipLastActive[id] = map[string]time.Time{host: time.Now()}
			}
			l.svc.mu.Unlock()
		}
	}

	if ok {
		l.logger().Infof("from %s accepted udp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted udp:%s [%s]",
			remote, reqAddr, nodeTag)
	}

	l.auditRequest(addr, id, reqAddr)
}

func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	fields := log.Fields{
		"remote":    addr.String(),
		"sessionID": sessionID,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 UDP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 UDP error")
	}
}
