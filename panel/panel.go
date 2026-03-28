package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/bunpanel"
	"github.com/XrayR-project/XrayR/api/gov2panel"
	"github.com/XrayR-project/XrayR/api/newV2board"
	"github.com/XrayR-project/XrayR/api/pmpanel"
	"github.com/XrayR-project/XrayR/api/proxypanel"
	"github.com/XrayR-project/XrayR/api/sspanel"
	"github.com/XrayR-project/XrayR/api/v2raysocks"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	_ "github.com/XrayR-project/XrayR/cmd/distro/all"
	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/XrayR-project/XrayR/service"
	"github.com/XrayR-project/XrayR/service/anytls"
	"github.com/XrayR-project/XrayR/service/controller"
	"github.com/XrayR-project/XrayR/service/hysteria2"
	"github.com/XrayR-project/XrayR/service/tuic"
)

// Panel Structure
type Panel struct {
	access                        sync.Mutex
	serverMutex                   sync.RWMutex
	serviceMutex                  sync.RWMutex
	panelConfig                   *Config
	Server                        *core.Instance
	Service                       []service.Service
	Running                       bool
	remotePanelConfigFetcher      remotePanelConfigFetcher
	remotePanelConfigSyncStop     chan struct{}
	remotePanelConfigSyncDone     chan struct{}
	remotePanelConfigSyncInterval time.Duration
	logger                        *log.Entry
}

type preparedNode struct {
	nodeConfig       *NodesConfig
	apiClient        api.API
	controllerConfig *controller.Config
	nodeType         string
}

type builtPanelRuntime struct {
	server   *core.Instance
	services []service.Service
}

func New(panelConfig *Config) *Panel {
	logger := log.WithFields(log.Fields{"module": "panel"})
	p := &Panel{
		panelConfig: panelConfig,
		logger:      logger,
	}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) (*core.Instance, error) {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			return nil, fmt.Errorf("read log config failed: %w", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read DNS config file at %s: %w", panelConfig.DnsConfigPath, err)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal DNS config %s: %w", panelConfig.DnsConfigPath, err)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to understand DNS config, please check https://xtls.github.io/config/dns.html for help: %w", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read routing config file at %s: %w", panelConfig.RouteConfigPath, err)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal routing config %s: %w", panelConfig.RouteConfigPath, err)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to understand routing config, please check https://xtls.github.io/config/routing.html for help: %w", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom inbound config file at %s: %w", panelConfig.InboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom inbound config %s: %w", panelConfig.InboundConfigPath, err)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to understand inbound config, please check https://xtls.github.io/config/inbound.html for help: %w", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom outbound config file at %s: %w", panelConfig.OutboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom outbound config %s: %w", panelConfig.OutboundConfigPath, err)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to understand outbound config, please check https://xtls.github.io/config/outbound.html for help: %w", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig, err := parseConnectionConfig(panelConfig.ConnectionConfig)
	if err != nil {
		return nil, err
	}
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %w", err)
	}

	return server, nil
}

// Start the panel
func (p *Panel) Start() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.logger.Info("Starting panel")
	preparedNodes, syncSettings, err := p.prepareNodesLocked()
	if err != nil {
		return err
	}

	if syncSettings.enabled {
		p.logger.Infof("Remote panel config sync enabled with interval %s", syncSettings.interval)
		if changes, err := p.syncRemotePanelConfigFilesLocked(syncSettings.fetcher); err != nil {
			p.logger.Warnf("Startup panel config prefetch failed: %v", err)
		} else if len(changes) > 0 {
			p.logger.Infof("Prefetched %d panel-level config file(s) before startup", len(changes))
		}
	} else if opts := p.buildRemotePanelConfigFetchOptionsLocked(); opts != nil {
		p.logger.Infof("Remote panel config sync disabled: %s", syncSettings.reason)
	}

	runtime, err := p.buildRuntimeLocked(preparedNodes)
	if err != nil {
		return err
	}
	if err := p.startBuiltRuntimeLocked(runtime, syncSettings, true); err != nil {
		return err
	}
	return nil
}

// Close the panel
func (p *Panel) Close() error {
	p.access.Lock()
	done := p.stopRemotePanelConfigSyncLocked()
	err := p.closeRuntimeLocked()
	p.access.Unlock()

	if done != nil {
		<-done
	}
	return err
}

func newAPIClient(nodeConfig *NodesConfig) (api.API, error) {
	if nodeConfig == nil {
		return nil, fmt.Errorf("node config is nil")
	}
	if nodeConfig.ApiConfig == nil {
		return nil, fmt.Errorf("node %q api config is nil", nodeConfig.PanelType)
	}

	switch nodeConfig.PanelType {
	case "SSpanel", "SSPanel":
		return sspanel.New(nodeConfig.ApiConfig), nil
	case "NewV2board", "V2board":
		return newV2board.New(nodeConfig.ApiConfig), nil
	case "PMpanel":
		return pmpanel.New(nodeConfig.ApiConfig), nil
	case "Proxypanel":
		return proxypanel.New(nodeConfig.ApiConfig), nil
	case "V2RaySocks":
		return v2raysocks.New(nodeConfig.ApiConfig), nil
	case "GoV2Panel":
		return gov2panel.New(nodeConfig.ApiConfig), nil
	case "BunPanel":
		return bunpanel.New(nodeConfig.ApiConfig), nil
	default:
		return nil, fmt.Errorf("unsupported panel type: %s", nodeConfig.PanelType)
	}
}

func (p *Panel) prepareNodesLocked() ([]preparedNode, remotePanelConfigSyncSettings, error) {
	preparedNodes := make([]preparedNode, 0, len(p.panelConfig.NodesConfig))
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		apiClient, err := newAPIClient(nodeConfig)
		if err != nil {
			return nil, remotePanelConfigSyncSettings{}, err
		}

		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				return nil, remotePanelConfigSyncSettings{}, fmt.Errorf("failed to read controller config: %w", err)
			}
		}

		// Merge panel-delivered cert config for XrayR (currently only SSPanel supports this).
		if panelCert, err := apiClient.GetXrayRCertConfig(); err != nil {
			p.logger.Warnf("Failed to get XrayR cert config from panel: %v", err)
		} else if panelCert != nil {
			if controllerConfig.CertConfig == nil {
				controllerConfig.CertConfig = &mylego.CertConfig{}
			}
			if controllerConfig.CertConfig.CertMode == "" {
				controllerConfig.CertConfig.CertMode = "dns"
			}
			if panelCert.Provider != "" {
				controllerConfig.CertConfig.Provider = panelCert.Provider
			}
			if panelCert.Email != "" {
				controllerConfig.CertConfig.Email = panelCert.Email
			}
			if len(panelCert.DNSEnv) > 0 {
				if controllerConfig.CertConfig.DNSEnv == nil {
					controllerConfig.CertConfig.DNSEnv = make(map[string]string)
				}
				for k, v := range panelCert.DNSEnv {
					controllerConfig.CertConfig.DNSEnv[k] = v
				}
			}
		}

		nodeType := apiClient.Describe().NodeType
		if nodeType == "" && nodeConfig.ApiConfig != nil {
			nodeType = nodeConfig.ApiConfig.NodeType
		}

		preparedNodes = append(preparedNodes, preparedNode{
			nodeConfig:       nodeConfig,
			apiClient:        apiClient,
			controllerConfig: controllerConfig,
			nodeType:         nodeType,
		})
	}

	return preparedNodes, p.resolveRemotePanelConfigSyncSettingsLocked(preparedNodes), nil
}

func (p *Panel) buildRuntimeLocked(preparedNodes []preparedNode) (*builtPanelRuntime, error) {
	server, err := p.loadCore(p.panelConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load core: %w", err)
	}

	services, err := p.buildServicesLocked(server, preparedNodes)
	if err != nil {
		if closeErr := server.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}

	return &builtPanelRuntime{server: server, services: services}, nil
}

func (p *Panel) buildServicesLocked(server *core.Instance, preparedNodes []preparedNode) ([]service.Service, error) {
	services := make([]service.Service, 0, len(preparedNodes))
	for _, node := range preparedNodes {
		var controllerService service.Service
		switch {
		case strings.EqualFold(node.nodeType, "Hysteria2"), strings.EqualFold(node.nodeType, "Hysteria"):
			controllerService = hysteria2.New(node.apiClient, node.controllerConfig)
		case strings.EqualFold(node.nodeType, "Tuic"):
			controllerService = tuic.New(node.apiClient, node.controllerConfig)
		case strings.EqualFold(node.nodeType, "AnyTLS"):
			controllerService = anytls.New(node.apiClient, node.controllerConfig)
		default:
			controllerService = controller.New(server, node.apiClient, node.controllerConfig, node.nodeConfig.PanelType)
		}
		services = append(services, controllerService)
	}
	return services, nil
}

func (p *Panel) startBuiltRuntimeLocked(runtime *builtPanelRuntime, syncSettings remotePanelConfigSyncSettings, startSyncLoop bool) error {
	if runtime == nil || runtime.server == nil {
		return fmt.Errorf("runtime is not initialized")
	}
	if err := runtime.server.Start(); err != nil {
		if closeErr := runtime.server.Close(); closeErr != nil {
			return errors.Join(fmt.Errorf("failed to start instance: %w", err), closeErr)
		}
		return fmt.Errorf("failed to start instance: %w", err)
	}

	started := make([]service.Service, 0, len(runtime.services))
	for _, s := range runtime.services {
		if err := s.Start(); err != nil {
			closeErr := closeBuiltRuntime(&builtPanelRuntime{
				server:   runtime.server,
				services: started,
			})
			if closeErr != nil {
				return errors.Join(fmt.Errorf("failed to start service: %w", err), closeErr)
			}
			return fmt.Errorf("failed to start service: %w", err)
		}
		started = append(started, s)
	}

	runtime.services = started
	p.serverMutex.Lock()
	p.Server = runtime.server
	p.serverMutex.Unlock()

	p.serviceMutex.Lock()
	p.Service = runtime.services
	p.serviceMutex.Unlock()

	if syncSettings.enabled {
		p.remotePanelConfigFetcher = syncSettings.fetcher
		p.remotePanelConfigSyncInterval = syncSettings.interval
	} else {
		p.remotePanelConfigFetcher = nil
		p.remotePanelConfigSyncInterval = 0
	}
	p.Running = true

	if startSyncLoop && syncSettings.enabled {
		p.startRemotePanelConfigSyncLocked()
	}
	return nil
}

func closeBuiltRuntime(runtime *builtPanelRuntime) error {
	if runtime == nil {
		return nil
	}

	var errs []error
	for _, s := range runtime.services {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if runtime.server != nil {
		if err := runtime.server.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Panel) closeRuntimeLocked() error {
	p.serviceMutex.RLock()
	services := make([]service.Service, len(p.Service))
	copy(services, p.Service)
	p.serviceMutex.RUnlock()

	p.serverMutex.RLock()
	server := p.Server
	p.serverMutex.RUnlock()

	runtime := &builtPanelRuntime{
		server:   server,
		services: services,
	}
	err := closeBuiltRuntime(runtime)

	p.serviceMutex.Lock()
	p.Service = nil
	p.serviceMutex.Unlock()

	p.serverMutex.Lock()
	p.Server = nil
	p.serverMutex.Unlock()

	p.Running = false
	return err
}

func (p *Panel) reloadAfterRemotePanelConfigChangeLocked(changes []remotePanelConfigFileChange) error {
	preparedNodes, syncSettings, err := p.prepareNodesLocked()
	if err != nil {
		rollbackErr := rollbackRemotePanelConfigChanges(changes)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("prepare runtime with new remote panel config: %w", err), rollbackErr)
		}
		return fmt.Errorf("prepare runtime with new remote panel config: %w", err)
	}

	newRuntime, err := p.buildRuntimeLocked(preparedNodes)
	if err != nil {
		rollbackErr := rollbackRemotePanelConfigChanges(changes)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("build runtime with new remote panel config: %w", err), rollbackErr)
		}
		return fmt.Errorf("build runtime with new remote panel config: %w", err)
	}

	if err := p.closeRuntimeLocked(); err != nil {
		p.logger.Warnf("Failed to close old runtime before remote config reload: %v", err)
	}

	startErr := p.startBuiltRuntimeLocked(newRuntime, syncSettings, false)
	if startErr == nil {
		return nil
	}

	rollbackErr := rollbackRemotePanelConfigChanges(changes)
	if rollbackErr != nil {
		p.remotePanelConfigFetcher = nil
		p.remotePanelConfigSyncInterval = 0
		return errors.Join(fmt.Errorf("start runtime with new remote panel config: %w", startErr), rollbackErr)
	}

	restoreNodes, restoreSync, err := p.prepareNodesLocked()
	if err != nil {
		p.remotePanelConfigFetcher = nil
		p.remotePanelConfigSyncInterval = 0
		return errors.Join(fmt.Errorf("start runtime with new remote panel config: %w", startErr), fmt.Errorf("prepare runtime after rollback: %w", err))
	}

	restoreRuntime, err := p.buildRuntimeLocked(restoreNodes)
	if err != nil {
		p.remotePanelConfigFetcher = nil
		p.remotePanelConfigSyncInterval = 0
		return errors.Join(fmt.Errorf("start runtime with new remote panel config: %w", startErr), fmt.Errorf("build runtime after rollback: %w", err))
	}

	if err := p.startBuiltRuntimeLocked(restoreRuntime, restoreSync, false); err != nil {
		p.remotePanelConfigFetcher = nil
		p.remotePanelConfigSyncInterval = 0
		return errors.Join(fmt.Errorf("start runtime with new remote panel config: %w", startErr), fmt.Errorf("restore old runtime after rollback: %w", err))
	}

	return fmt.Errorf("start runtime with new remote panel config: %w", startErr)
}

func parseConnectionConfig(c *ConnectionConfig) (*conf.Policy, error) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			return nil, fmt.Errorf("read connection config failed: %w", err)
		}
	}
	policy := &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return policy, nil
}
