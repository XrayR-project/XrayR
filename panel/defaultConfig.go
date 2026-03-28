package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/service/controller"
)

const remotePanelConfigFilePerm os.FileMode = 0o644

type remotePanelConfigFetcher interface {
	FetchRemotePanelConfigFiles(opts *api.RemotePanelConfigFetchOptions) (*api.RemotePanelConfigFiles, error)
}

type remotePanelConfigSyncSettings struct {
	enabled  bool
	fetcher  remotePanelConfigFetcher
	interval time.Duration
	reason   string
}

type remotePanelConfigFileChange struct {
	label         string
	path          string
	oldContent    []byte
	hadOldContent bool
	newContent    []byte
}

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
	}
}

func getDefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Handshake:    4,
		ConnIdle:     30,
		UplinkOnly:   2,
		DownlinkOnly: 4,
		BufferSize:   4, // 4KB per connection; 64KB was too high for 10k-50k users (would consume 3.2GB+ RAM)
	}
}

func getDefaultControllerConfig() *controller.Config {
	return &controller.Config{
		ListenIP:       "0.0.0.0",
		SendIP:         "0.0.0.0",
		UpdatePeriodic: 60,
		DNSType:        "AsIs",
	}
}

func (p *Panel) buildRemotePanelConfigFetchOptionsLocked() *api.RemotePanelConfigFetchOptions {
	opts := &api.RemotePanelConfigFetchOptions{
		DNS:      p.panelConfig != nil && p.panelConfig.DnsConfigPath != "",
		Route:    p.panelConfig != nil && p.panelConfig.RouteConfigPath != "",
		Inbound:  p.panelConfig != nil && p.panelConfig.InboundConfigPath != "",
		Outbound: p.panelConfig != nil && p.panelConfig.OutboundConfigPath != "",
	}
	if !opts.Any() {
		return nil
	}
	return opts
}

func (p *Panel) resolveRemotePanelConfigSyncSettingsLocked(nodes []preparedNode) remotePanelConfigSyncSettings {
	opts := p.buildRemotePanelConfigFetchOptionsLocked()
	if opts == nil {
		return remotePanelConfigSyncSettings{reason: "no panel-level config file paths are configured"}
	}
	if len(nodes) != 1 {
		return remotePanelConfigSyncSettings{reason: fmt.Sprintf("requires exactly one valid node, got %d", len(nodes))}
	}

	fetcher, ok := nodes[0].apiClient.(remotePanelConfigFetcher)
	if !ok {
		return remotePanelConfigSyncSettings{reason: "the only node does not expose remote panel config fetch support"}
	}

	interval := time.Duration(nodes[0].controllerConfig.UpdatePeriodic) * time.Minute
	if interval <= 0 {
		interval = time.Duration(getDefaultControllerConfig().UpdatePeriodic) * time.Minute
	}

	return remotePanelConfigSyncSettings{
		enabled:  true,
		fetcher:  fetcher,
		interval: interval,
	}
}

func (p *Panel) syncRemotePanelConfigFilesLocked(fetcher remotePanelConfigFetcher) ([]remotePanelConfigFileChange, error) {
	if fetcher == nil {
		return nil, nil
	}
	opts := p.buildRemotePanelConfigFetchOptionsLocked()
	if opts == nil {
		return nil, nil
	}

	files, err := fetcher.FetchRemotePanelConfigFiles(opts)
	if err != nil {
		return nil, err
	}
	if files == nil {
		return nil, nil
	}

	var changes []remotePanelConfigFileChange
	appendChange := func(label, path string, body []byte, validator func([]byte) error) error {
		change, err := prepareRemotePanelConfigChange(label, path, body, validator)
		if err != nil {
			return err
		}
		if change != nil {
			changes = append(changes, *change)
		}
		return nil
	}

	if opts.DNS {
		if err := appendChange("dns", p.panelConfig.DnsConfigPath, files.DNS, validateRemoteDNSConfig); err != nil {
			return nil, err
		}
	}
	if opts.Route {
		if err := appendChange("route", p.panelConfig.RouteConfigPath, files.Route, validateRemoteRouteConfig); err != nil {
			return nil, err
		}
	}
	if opts.Inbound {
		if err := appendChange("inbound", p.panelConfig.InboundConfigPath, files.Inbound, validateRemoteInboundConfig); err != nil {
			return nil, err
		}
	}
	if opts.Outbound {
		if err := appendChange("outbound", p.panelConfig.OutboundConfigPath, files.Outbound, validateRemoteOutboundConfig); err != nil {
			return nil, err
		}
	}

	var applied []remotePanelConfigFileChange
	for _, change := range changes {
		if err := atomicWritePanelConfigFile(change.path, change.newContent); err != nil {
			rollbackErr := rollbackRemotePanelConfigChanges(applied)
			if rollbackErr != nil {
				return nil, errors.Join(fmt.Errorf("write %s config file %s: %w", change.label, change.path, err), rollbackErr)
			}
			return nil, fmt.Errorf("write %s config file %s: %w", change.label, change.path, err)
		}
		applied = append(applied, change)
	}
	return changes, nil
}

func prepareRemotePanelConfigChange(label, path string, body []byte, validator func([]byte) error) (*remotePanelConfigFileChange, error) {
	if path == "" {
		return nil, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	if err := validator(body); err != nil {
		return nil, fmt.Errorf("validate %s config from panel failed: %w", label, err)
	}

	oldContent, hadOldContent, err := readPanelConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("read local %s config file %s: %w", label, path, err)
	}
	if hadOldContent && bytes.Equal(body, oldContent) {
		return nil, nil
	}
	if !hadOldContent && len(body) == 0 {
		return nil, nil
	}

	return &remotePanelConfigFileChange{
		label:         label,
		path:          path,
		oldContent:    oldContent,
		hadOldContent: hadOldContent,
		newContent:    body,
	}, nil
}

func validateRemoteDNSConfig(body []byte) error {
	cfg := &conf.DNSConfig{}
	if err := json.Unmarshal(body, cfg); err != nil {
		return fmt.Errorf("unmarshal DNS config: %w", err)
	}
	if _, err := cfg.Build(); err != nil {
		return fmt.Errorf("build DNS config: %w", err)
	}
	return nil
}

func validateRemoteRouteConfig(body []byte) error {
	cfg := &conf.RouterConfig{}
	if err := json.Unmarshal(body, cfg); err != nil {
		return fmt.Errorf("unmarshal routing config: %w", err)
	}
	if _, err := cfg.Build(); err != nil {
		return fmt.Errorf("build routing config: %w", err)
	}
	return nil
}

func validateRemoteInboundConfig(body []byte) error {
	var cfg []conf.InboundDetourConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return fmt.Errorf("unmarshal custom inbound config: %w", err)
	}
	for i, item := range cfg {
		if _, err := item.Build(); err != nil {
			return fmt.Errorf("build custom inbound config at index %d: %w", i, err)
		}
	}
	return nil
}

func validateRemoteOutboundConfig(body []byte) error {
	var cfg []conf.OutboundDetourConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return fmt.Errorf("unmarshal custom outbound config: %w", err)
	}
	for i, item := range cfg {
		if _, err := item.Build(); err != nil {
			return fmt.Errorf("build custom outbound config at index %d: %w", i, err)
		}
	}
	return nil
}

func readPanelConfigFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func atomicWritePanelConfigFile(path string, data []byte) error {
	perm, err := panelConfigFilePermForPath(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

func panelConfigFilePermForPath(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return remotePanelConfigFilePerm, nil
		}
		return 0, err
	}
	return info.Mode().Perm(), nil
}

func rollbackRemotePanelConfigChanges(changes []remotePanelConfigFileChange) error {
	var errs []error
	for i := len(changes) - 1; i >= 0; i-- {
		change := changes[i]
		if change.hadOldContent {
			if err := atomicWritePanelConfigFile(change.path, change.oldContent); err != nil {
				errs = append(errs, fmt.Errorf("rollback %s config file %s: %w", change.label, change.path, err))
			}
			continue
		}
		if err := os.Remove(change.path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove new %s config file %s during rollback: %w", change.label, change.path, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Panel) stopRemotePanelConfigSyncLocked() chan struct{} {
	stop := p.remotePanelConfigSyncStop
	done := p.remotePanelConfigSyncDone
	if stop != nil {
		close(stop)
	}
	p.remotePanelConfigSyncStop = nil
	p.remotePanelConfigSyncDone = nil
	p.remotePanelConfigFetcher = nil
	p.remotePanelConfigSyncInterval = 0
	return done
}

func (p *Panel) startRemotePanelConfigSyncLocked() {
	if p.remotePanelConfigFetcher == nil || p.remotePanelConfigSyncInterval <= 0 || p.remotePanelConfigSyncStop != nil {
		return
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	interval := p.remotePanelConfigSyncInterval
	p.remotePanelConfigSyncStop = stop
	p.remotePanelConfigSyncDone = done

	go p.remotePanelConfigSyncLoop(stop, done, interval)
}

func (p *Panel) remotePanelConfigSyncLoop(stop <-chan struct{}, done chan<- struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(done)

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.remotePanelConfigSyncTick(stop)
		}
	}
}

func (p *Panel) remotePanelConfigSyncTick(stop <-chan struct{}) {
	p.access.Lock()
	defer p.access.Unlock()

	select {
	case <-stop:
		return
	default:
	}

	if !p.Running || p.remotePanelConfigFetcher == nil {
		return
	}

	changes, err := p.syncRemotePanelConfigFilesLocked(p.remotePanelConfigFetcher)
	if err != nil {
		p.logger.Warnf("Remote panel config sync failed: %v", err)
		return
	}
	if len(changes) == 0 {
		return
	}

	p.logger.Infof("Remote panel config changed (%d file(s)); reloading panel runtime", len(changes))
	if err := p.reloadAfterRemotePanelConfigChangeLocked(changes); err != nil {
		p.logger.Errorf("Remote panel config reload failed: %v", err)
		if !p.Running {
			p.stopRemotePanelConfigSyncLocked()
		}
	}
}
