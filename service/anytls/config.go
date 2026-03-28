package anytls

import (
	"context"
	"fmt"
	"net/netip"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/XrayR-project/XrayR/common/mylego"
)

func (s *AnyTLSService) buildSingBox() (*box.Box, string, error) {
	listenIP := s.config.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(listenIP)
	if err != nil {
		return nil, "", fmt.Errorf("invalid ListenIP %s: %w", listenIP, err)
	}
	port := s.nodeInfo.Port
	if port == 0 {
		return nil, "", fmt.Errorf("invalid port 0")
	}

	certFile, keyFile, err := getOrIssueCert(s.config.CertConfig)
	if err != nil {
		return nil, "", err
	}

	ctx := context.Background()
	ctx = box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())

	opts := option.Options{
		Log: &option.LogOptions{
			Level:     "warn",
			Timestamp: true,
		},
	}

	listen := option.ListenOptions{
		Listen:     (*badoption.Addr)(&addr),
		ListenPort: uint16(port),
	}

	tlsOpt := &option.InboundTLSOptions{
		Enabled:         true,
		CertificatePath: certFile,
		KeyPath:         keyFile,
	}

	padding := []string{}
	if s.nodeInfo.AnyTLSConfig != nil && len(s.nodeInfo.AnyTLSConfig.PaddingScheme) > 0 {
		padding = s.nodeInfo.AnyTLSConfig.PaddingScheme
	}

	s.mu.RLock()
	users := make([]option.AnyTLSUser, len(s.authUsers))
	copy(users, s.authUsers)
	s.mu.RUnlock()

	inOpts := &option.AnyTLSInboundOptions{
		ListenOptions: listen,
		Users:         users,
		PaddingScheme: padding,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: tlsOpt,
		},
	}

	opts.Inbounds = []option.Inbound{
		{
			Type:    "anytls",
			Tag:     s.inboundTag,
			Options: inOpts,
		},
	}
	opts.Outbounds = []option.Outbound{
		{
			Type:    "direct",
			Tag:     "direct",
			Options: &option.DirectOutboundOptions{},
		},
	}

	boxInstance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, "", err
	}

	tracker := &anyTLSTracker{svc: s}
	boxInstance.Router().AppendTracker(tracker)

	return boxInstance, s.inboundTag, nil
}

func getOrIssueCert(certConfig *mylego.CertConfig) (string, string, error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("CertConfig is nil")
	}
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
		return lego.DNSCert()
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		return lego.HTTPCert()
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

// certMonitor checks and renews the AnyTLS certificate when needed. When a
// renewal actually happens (ok == true), the AnyTLS sing-box instance is
// hot-reloaded so the new certificate is picked up without restarting the
// whole XrayR process.
func (s *AnyTLSService) certMonitor() error {
	if s.config == nil || s.config.CertConfig == nil {
		return nil
	}

	if !s.nodeInfo.EnableTLS {
		return nil
	}

	switch s.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		lego, err := mylego.New(s.config.CertConfig)
		if err != nil {
			s.logger.Print(err)
			return nil
		}
		certPath, keyPath, ok, err := lego.RenewCert()
		if err != nil {
			s.logger.Print(err)
			return nil
		}
		if ok {
			s.logger.Infof("AnyTLS certificate renewed for %s, reloading node (cert=%s, key=%s)", s.config.CertConfig.CertDomain, certPath, keyPath)
			if err := s.reloadNode(s.nodeInfo); err != nil {
				s.logger.Printf("AnyTLS certificate reload failed: %v", err)
			}
		}
	}

	return nil
}
