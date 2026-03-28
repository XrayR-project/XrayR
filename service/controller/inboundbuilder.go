// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
)

// InboundBuilderWithUsers builds an Inbound config for socks/http protocols with all users
// embedded in the protocol config. These protocols don't support xray-core's proxy.UserManager
// interface, so users must be included at build time.
func InboundBuilderWithUsers(config *Config, nodeInfo *api.NodeInfo, tag string, userInfo *[]api.UserInfo) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList
	inboundDetourConfig.Tag = tag

	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var proxySetting any
	var protocol string

	switch nodeInfo.NodeType {
	case "Socks":
		protocol = "socks"
		accounts := make([]*conf.SocksAccount, 0, len(*userInfo))
		for _, u := range *userInfo {
			if u.UUID == "" {
				continue
			}
			accounts = append(accounts, &conf.SocksAccount{
				Username: u.UUID,
				Password: u.UUID,
			})
		}
		proxySetting = &conf.SocksServerConfig{
			AuthMethod: "password",
			Accounts:   accounts,
			UDP:        true,
		}
	case "HTTP":
		protocol = "http"
		accounts := make([]*conf.HTTPAccount, 0, len(*userInfo))
		for _, u := range *userInfo {
			if u.UUID == "" {
				continue
			}
			accounts = append(accounts, &conf.HTTPAccount{
				Username: u.UUID,
				Password: u.UUID,
			})
		}
		proxySetting = &conf.HTTPServerConfig{
			Accounts: accounts,
		}
	default:
		return nil, fmt.Errorf("InboundBuilderWithUsers only supports Socks and HTTP, got: %s", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	rawSetting := json.RawMessage(setting)
	inboundDetourConfig.Settings = &rawSetting

	// Build streamSettings (tcp only for socks/http)
	streamSetting := new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol("tcp")
	streamSetting.Network = &transportProtocol
	tcpSetting := &conf.TCPConfig{
		AcceptProxyProtocol: config.EnableProxyProtocol,
	}
	streamSetting.TCPSettings = tcpSetting

	// TLS for HTTP proxy (HTTPS)
	if nodeInfo.EnableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(config.CertConfig)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}

	inboundDetourConfig.StreamSetting = streamSetting
	return inboundDetourConfig.Build()
}

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		// Shdowsocks listen in 127.0.0.1 for safety
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless", "VLESS":
		//  Protocol selection is driven solely by NodeType
		useVless := nodeInfo.EnableVless || strings.EqualFold(nodeInfo.NodeType, "Vless") || strings.EqualFold(nodeInfo.NodeType, "VLESS")
		if useVless {
			protocol = "vless"
			if config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: "none",
						Fallbacks:  fallbackConfigs,
					}
				} else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: "none",
				}
			}
		} else {
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}
		}
	case "Trojan":
		protocol = "trojan"
		if config.EnableFallback {
			fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.TrojanServerConfig{
					Fallbacks: fallbackConfigs,
				}
			} else {
				return nil, err
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "Shadowsocks", "Shadowsocks-Plugin":
		protocol = "shadowsocks"
		cipher := strings.ToLower(nodeInfo.CypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate random password: %w", err)
		}
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}

	case "dokodemo-door":
		protocol = "dokodemo-door"
		proxySetting = struct {
			Host        string   `json:"address"`
			NetworkList []string `json:"network"`
		}{
			Host:        "v1.mux.cool",
			NetworkList: []string{"tcp", "udp"},
		}
	case "Socks":
		protocol = "socks"
		proxySetting = &conf.SocksServerConfig{
			AuthMethod: "password",
			Accounts:   []*conf.SocksAccount{}, // users managed via full rebuild
			UDP:        true,
		}
	case "HTTP":
		protocol = "http"
		proxySetting = &conf.HTTPServerConfig{
			Accounts: []*conf.HTTPAccount{}, // users managed via full rebuild
		}
	default:
		return nil, fmt.Errorf("unsupported node type: %s, Only support: Vmess, VLESS, Trojan, Shadowsocks, Shadowsocks-Plugin, Socks, and HTTP", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || nodeInfo.AcceptProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || nodeInfo.AcceptProxyProtocol,
			Host:                nodeInfo.Host,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
			Authority:   nodeInfo.Authority,
		}
		streamSetting.GRPCSettings = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
			Headers:             nodeInfo.Headers,
			Path:                nodeInfo.Path,
			Host:                nodeInfo.Host,
			AcceptProxyProtocol: config.EnableProxyProtocol || nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings
	case "splithttp", "xhttp":
		splithttpSetting := &conf.SplitHTTPConfig{
			Path:                nodeInfo.Path,
			Host:                nodeInfo.Host,
			Mode:                nodeInfo.XHTTPMode,
			Extra:               nodeInfo.XHTTPExtra,
			XPaddingObfsMode:    nodeInfo.XPaddingObfsMode,
			XPaddingKey:         nodeInfo.XPaddingKey,
			XPaddingHeader:      nodeInfo.XPaddingHeader,
			XPaddingPlacement:   nodeInfo.XPaddingPlacement,
			XPaddingMethod:      nodeInfo.XPaddingMethod,
			UplinkHTTPMethod:    nodeInfo.UplinkHTTPMethod,
			SessionPlacement:    nodeInfo.SessionPlacement,
			SessionKey:          nodeInfo.SessionKey,
			SeqPlacement:        nodeInfo.SeqPlacement,
			SeqKey:              nodeInfo.SeqKey,
			UplinkDataPlacement: nodeInfo.UplinkDataPlacement,
			UplinkDataKey:       nodeInfo.UplinkDataKey,
			UplinkChunkSize:     nodeInfo.UplinkChunkSize,
			NoGRPCHeader:        nodeInfo.NoGRPCHeader,
			NoSSEHeader:         nodeInfo.NoSSEHeader,
			ScMaxBufferedPosts:  nodeInfo.ScMaxBufferedPosts,
			Headers:             nodeInfo.Headers,
		}
		if nodeInfo.XPaddingBytes != nil {
			splithttpSetting.XPaddingBytes = conf.Int32Range{
				From: nodeInfo.XPaddingBytes[0],
				To:   nodeInfo.XPaddingBytes[1],
			}
		}
		if nodeInfo.ScMaxEachPostBytes != nil {
			splithttpSetting.ScMaxEachPostBytes = conf.Int32Range{
				From: nodeInfo.ScMaxEachPostBytes[0],
				To:   nodeInfo.ScMaxEachPostBytes[1],
			}
		}
		if nodeInfo.ScMinPostsIntervalMs != nil {
			splithttpSetting.ScMinPostsIntervalMs = conf.Int32Range{
				From: nodeInfo.ScMinPostsIntervalMs[0],
				To:   nodeInfo.ScMinPostsIntervalMs[1],
			}
		}
		if nodeInfo.ScStreamUpServerSecs != nil {
			splithttpSetting.ScStreamUpServerSecs = conf.Int32Range{
				From: nodeInfo.ScStreamUpServerSecs[0],
				To:   nodeInfo.ScStreamUpServerSecs[1],
			}
		}
		if nodeInfo.XmuxMaxConcurrency != nil || nodeInfo.XmuxMaxConnections != nil {
			splithttpSetting.Xmux = conf.XmuxConfig{
				HKeepAlivePeriod: nodeInfo.XmuxHKeepAlivePeriod,
			}
			if nodeInfo.XmuxMaxConcurrency != nil {
				splithttpSetting.Xmux.MaxConcurrency = conf.Int32Range{
					From: nodeInfo.XmuxMaxConcurrency[0],
					To:   nodeInfo.XmuxMaxConcurrency[1],
				}
			}
			if nodeInfo.XmuxMaxConnections != nil {
				splithttpSetting.Xmux.MaxConnections = conf.Int32Range{
					From: nodeInfo.XmuxMaxConnections[0],
					To:   nodeInfo.XmuxMaxConnections[1],
				}
			}
			if nodeInfo.XmuxCMaxReuseTimes != nil {
				splithttpSetting.Xmux.CMaxReuseTimes = conf.Int32Range{
					From: nodeInfo.XmuxCMaxReuseTimes[0],
					To:   nodeInfo.XmuxCMaxReuseTimes[1],
				}
			}
			if nodeInfo.XmuxHMaxRequestTimes != nil {
				splithttpSetting.Xmux.HMaxRequestTimes = conf.Int32Range{
					From: nodeInfo.XmuxHMaxRequestTimes[0],
					To:   nodeInfo.XmuxHMaxRequestTimes[1],
				}
			}
			if nodeInfo.XmuxHMaxReusableSecs != nil {
				splithttpSetting.Xmux.HMaxReusableSecs = conf.Int32Range{
					From: nodeInfo.XmuxHMaxReusableSecs[0],
					To:   nodeInfo.XmuxHMaxReusableSecs[1],
				}
			}
		}
		streamSetting.SplitHTTPSettings = splithttpSetting
	}
	streamSetting.Network = &transportProtocol

	// Build TLS and REALITY settings
	var isREALITY bool
	// Prefer panel-provided REALITY settings; do not fall back to config.yml keys.
	if nodeInfo.REALITYConfig != nil && nodeInfo.EnableREALITY {
		r := nodeInfo.REALITYConfig
		if r.Dest != "" && r.PrivateKey != "" {
			isREALITY = true
			streamSetting.Security = "reality"
			streamSetting.REALITYSettings = &conf.REALITYConfig{
				Dest:         []byte(`"` + r.Dest + `"`),
				Xver:         r.ProxyProtocolVer,
				ServerNames:  r.ServerNames,
				PrivateKey:   r.PrivateKey,
				MinClientVer: r.MinClientVer,
				MaxClientVer: r.MaxClientVer,
				MaxTimeDiff:  r.MaxTimeDiff,
				ShortIds:     r.ShortIds,
			}
		}
	}

	if !isREALITY && nodeInfo.EnableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(config.CertConfig)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}

	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && (config.EnableProxyProtocol || nodeInfo.AcceptProxyProtocol) {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol || nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig) (certFile string, keyFile string, err error) {
	switch certConfig.CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
