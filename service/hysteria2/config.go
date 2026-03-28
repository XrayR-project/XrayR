package hysteria2

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/obfs"

	"github.com/XrayR-project/XrayR/common/mylego"
)

// buildServerConfig constructs the Hysteria2 server configuration based on
// the current node information and controller configuration.
func (h *Hysteria2Service) buildServerConfig() (*server.Config, error) {
	hy := h.nodeInfo.Hysteria2Config
	if hy == nil {
		return nil, fmt.Errorf("Hysteria2Config is nil")
	}

	listenIP := h.config.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", listenIP, h.nodeInfo.Port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %s: %w", addr, err)
	}

	udpConn, err := correctnet.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}

	var packetConn net.PacketConn = udpConn

	// Obfuscation
	obfsType := hy.Obfs
	if obfsType == "" {
		obfsType = "salamander"
	}
	switch obfsType {
	case "salamander":
		if hy.ObfsPassword == "" {
			udpConn.Close()
			return nil, fmt.Errorf("obfs_password is required when obfs is salamander")
		}
		ob, err := obfs.NewSalamanderObfuscator([]byte(hy.ObfsPassword))
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("failed to create salamander obfuscator")
		}
		packetConn = obfs.WrapPacketConn(udpConn, ob)
	case "", "none", "plain":
		// no obfuscation
	default:
		udpConn.Close()
		return nil, fmt.Errorf("unsupported hysteria2 obfs: %s", hy.Obfs)
	}

	certFile, keyFile, err := getOrIssueCert(h.config.CertConfig)
	if err != nil {
		packetConn.Close()
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("load tls cert: %w", err)
	}

	bandwidth := server.BandwidthConfig{}
	if hy.UpMbps > 0 {
		bandwidth.MaxTx = uint64(hy.UpMbps) * 1000000 / 8
	}
	if hy.DownMbps > 0 {
		bandwidth.MaxRx = uint64(hy.DownMbps) * 1000000 / 8
	}

	cfg := &server.Config{
		TLSConfig: server.TLSConfig{
			Certificates: []tls.Certificate{cert},
		},
		QUICConfig: server.QUICConfig{},
		Conn:       packetConn,

		BandwidthConfig:       bandwidth,
		IgnoreClientBandwidth: hy.IgnoreClientBandwidth,
		Authenticator:         &hyAuthenticator{svc: h},
		EventLogger:           &hyEventLogger{svc: h},
		TrafficLogger:         &hyTrafficLogger{svc: h},
	}

	return cfg, nil
}

// getOrIssueCert mirrors controller.getCertFile but is local to the hysteria2
// package so we do not have to depend on unexported symbols.
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

// certMonitor checks and renews the certificate when needed.
func (h *Hysteria2Service) certMonitor() error {
	if h.config == nil || h.config.CertConfig == nil {
		return nil
	}

	if !h.nodeInfo.EnableTLS {
		return nil
	}

	switch h.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		lego, err := mylego.New(h.config.CertConfig)
		if err != nil {
			h.logger.Print(err)
			return nil
		}
		certPath, keyPath, ok, err := lego.RenewCert()
		if err != nil {
			h.logger.Print(err)
			return nil
		}
		// ok == true means the certificate was actually renewed on disk.
		// Rebuild the Hysteria2 server so the new cert is loaded without
		// requiring a full XrayR restart.
		if ok {
			h.logger.Infof("Hysteria2 certificate renewed for %s, reloading server (cert=%s, key=%s)", h.config.CertConfig.CertDomain, certPath, keyPath)
			if err := h.reloadNode(h.nodeInfo); err != nil {
				h.logger.Printf("Hysteria2 certificate reload failed: %v", err)
			}
		}
	}

	return nil
}
