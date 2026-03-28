package tuic

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/rule"
	"github.com/XrayR-project/XrayR/service"
	"github.com/XrayR-project/XrayR/service/controller"
)

var _ service.Service = (*TuicService)(nil)

func New(apiClient api.API, cfg *controller.Config) *TuicService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	return &TuicService{
		apiClient:    apiClient,
		config:       cfg,
		logger:       logger,
		rules:        rule.New(),
		users:        make(map[string]userRecord),
		traffic:      make(map[string]*userTraffic),
		onlineIPs:    make(map[string]map[string]struct{}),
		ipLastActive: make(map[string]map[string]time.Time),
	}
}

func (s *TuicService) Start() error {
	s.clientInfo = s.apiClient.Describe()

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		return fmt.Errorf("TuicService can only be used with Tuic node, got %v", nodeInfo)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for TUIC")
	}
	if nodeInfo.TuicConfig == nil {
		nodeInfo.TuicConfig = &api.TuicConfig{}
	}

	s.nodeInfo = nodeInfo
	// Ensure tag is unique per TUIC node by embedding NodeID so that
	// limiter and rule manager state remain per-node, even when
	// multiple TUIC nodes share the same listen endpoint.
	s.tag = fmt.Sprintf("%s_%s_%d_%d", s.nodeInfo.NodeType, s.config.ListenIP, s.nodeInfo.Port, s.nodeInfo.NodeID)
	s.startAt = time.Now()
	s.inboundTag = s.tag

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return err
	}
	if userInfo == nil || len(*userInfo) == 0 {
		s.logger.Warn("No users found for TUIC node, authentication may fail")
	} else {
		s.logger.Infof("Syncing %d users for TUIC node", len(*userInfo))
	}
	s.syncUsers(userInfo)

	// Initial rule list.
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			s.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := s.rules.UpdateRule(s.tag, *ruleList); err != nil {
				s.logger.Print(err)
			}
		}
	}

	boxInstance, _, err := s.buildSingBox()
	if err != nil {
		return err
	}
	s.box = boxInstance

	go func() {
		if err := s.box.Start(); err != nil {
			s.logger.Errorf("TUIC sing-box start error: %v", err)
		}
	}()

	interval := time.Duration(s.config.UpdatePeriodic) * time.Second
	s.tasks = []periodicTask{
		{
			tag: s.tag,
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  s.userMonitor,
			},
		},
		{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  s.nodeMonitor,
			},
		},
	}

	if s.nodeInfo.EnableTLS {
		s.tasks = append(s.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(s.config.UpdatePeriodic) * time.Second * 60,
				Execute:  s.certMonitor,
			},
		})
	}

	for _, t := range s.tasks {
		go t.Start()
	}

	s.logger.Infof("TUIC node started on %s:%d (sing-box %s)", s.config.ListenIP, s.nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *TuicService) Close() error {
	for _, t := range s.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	s.tasks = nil
	if s.box != nil {
		return s.box.Close()
	}
	return nil
}

// reloadNode replaces in-memory node information and rebuilds the underlying
// sing-box TUIC instance so that changes from the panel (port, TLS/SNI,
// congestion control, etc.) and renewed certificates take effect without
// restarting the whole XrayR process.
func (s *TuicService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "Tuic" {
		return fmt.Errorf("TuicService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for TUIC")
	}
	if nodeInfo.TuicConfig == nil {
		nodeInfo.TuicConfig = &api.TuicConfig{}
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	oldInfo := s.nodeInfo
	s.nodeInfo = nodeInfo

	// Keep CertDomain in sync with the panel SNI when originally derived from
	// SNI/Host.
	if s.config.CertConfig != nil && s.nodeInfo.EnableTLS && !s.nodeInfo.EnableREALITY {
		sni := s.nodeInfo.SNI
		if sni == "" {
			sni = s.nodeInfo.Host
		}
		if sni != "" {
			cert := s.config.CertConfig
			var oldSNI, oldHost string
			if oldInfo != nil {
				oldSNI = oldInfo.SNI
				oldHost = oldInfo.Host
			}
			switch cert.CertMode {
			case "file":
				if cert.CertFile == "" && cert.KeyFile == "" {
					cert.CertDomain = sni
					cert.CertFile = "/etc/XrayR/cert/" + sni + ".cert"
					cert.KeyFile = "/etc/XrayR/cert/" + sni + ".key"
				} else if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
					cert.CertDomain = sni
				}
			case "dns", "http", "tls":
				if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
					cert.CertDomain = sni
				}
			}
		}
	}

	if s.box != nil {
		if err := s.box.Close(); err != nil {
			s.logger.Printf("TUIC reload: failed to close old box: %v", err)
		}
		s.box = nil
	}

	boxInstance, inboundTag, err := s.buildSingBox()
	if err != nil {
		return err
	}
	s.box = boxInstance
	s.inboundTag = inboundTag

	go func() {
		if err := s.box.Start(); err != nil {
			s.logger.Errorf("TUIC box start error after reload: %v", err)
		}
	}()

	s.logger.Infof("TUIC node reloaded on %s:%d", s.config.ListenIP, s.nodeInfo.Port)
	return nil
}

func getSingBoxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
			if dep.Version != "" {
				return dep.Version
			}
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			break
		}
	}
	return "unknown"
}
