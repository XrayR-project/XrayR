package hysteria2

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// hyAuthenticator implements server.Authenticator and performs user lookup
// and local device limit enforcement based on SSPanel's UUID.
type hyAuthenticator struct {
	svc *Hysteria2Service
}

func (a *hyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	logger := log.NewEntry(log.StandardLogger())
	if a.svc != nil && a.svc.logger != nil {
		logger = a.svc.logger
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		host = h
	}

	if auth == "" {
		logger.WithField("remote", host).Warn("Hysteria2 auth failed: empty auth string")
		return false, ""
	}

	a.svc.mu.Lock()
	defer a.svc.mu.Unlock()

	user, ok := a.svc.users[auth]
	if !ok {
		logger.WithFields(log.Fields{
			"remote": host,
			"auth":   auth,
		}).Warn("Hysteria2 auth failed: unknown UUID")
		return false, ""
	}

	ipSet, ok := a.svc.onlineIPs[auth]
	if !ok {
		ipSet = make(map[string]struct{})
		a.svc.onlineIPs[auth] = ipSet
	}

	// Initialize ipLastActive map for this user if not exists
	activeMap, ok := a.svc.ipLastActive[auth]
	if !ok {
		activeMap = make(map[string]time.Time)
		a.svc.ipLastActive[auth] = activeMap
	}

	if _, exists := ipSet[host]; !exists {
		// New device
		if user.DeviceLimit > 0 && len(ipSet) >= user.DeviceLimit {
			logger.WithFields(log.Fields{
				"uid":         user.UID,
				"deviceLimit": user.DeviceLimit,
				"remote":      host,
			}).Warn("Hysteria2 user exceeded device limit")
			return false, ""
		}
		ipSet[host] = struct{}{}
	}

	// Update last active time for this IP
	activeMap[host] = time.Now()

	return true, auth
}
