package hysteria2

import (
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/rule"
	"github.com/XrayR-project/XrayR/service/controller"
)

type Hysteria2Service struct {
	apiClient api.API
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	server server.Server

	tag     string
	startAt time.Time
	tasks   []periodicTask
	logger  *log.Entry

	rules *rule.Manager

	mu           sync.RWMutex
	users        map[string]userRecord           // uuid -> user
	traffic      map[string]*userTraffic         // uuid -> counters
	overLimit    map[string]bool                 // uuid -> over device limit
	onlineIPs    map[string]map[string]struct{}  // uuid -> set of IPs
	ipLastActive map[string]map[string]time.Time // uuid -> ip -> last active time
	blockedIDs   map[string]bool                 // connection id -> blocked by audit
	rateLimiters map[string]*rate.Limiter        // uuid -> per-user speed limiter

	// reloadMu serializes hot-reload operations (node / cert changes) so that
	// we never rebuild the underlying Hysteria2 server concurrently from
	// multiple goroutines (nodeMonitor, certMonitor, Start).
	reloadMu sync.Mutex

	// portHopRules keeps track of the iptables rules we added for Hysteria2
	// port hopping so that we can reliably remove or update them when the
	// panel configuration changes or the service stops.
	portHopRules []portHopRule
}

type userRecord struct {
	UID         int
	Email       string
	DeviceLimit int
	SpeedLimit  uint64
}

type userTraffic struct {
	Upload   int64
	Download int64
}

// portHopRule describes a single iptables REDIRECT rule for a contiguous
// destination port range. FromPortStart and FromPortEnd are inclusive. ToPort
// is the underlying Hysteria2 server port (offset_port_node) to which traffic
// is redirected.
type portHopRule struct {
	FromPortStart uint16
	FromPortEnd   uint16
	ToPort        uint16
}

type periodicTask struct {
	tag string
	*task.Periodic
}
