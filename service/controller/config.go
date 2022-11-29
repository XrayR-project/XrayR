package controller

import (
	"github.com/XrayR-project/XrayR/common/mylego"
)

type Config struct {
	ListenIP             string                `mapstructure:"ListenIP"`
	SendIP               string                `mapstructure:"SendIP"`
	UpdatePeriodic       int                   `mapstructure:"UpdatePeriodic"`
	CertConfig           *mylego.CertConfig    `mapstructure:"CertConfig"`
	EnableDNS            bool                  `mapstructure:"EnableDNS"`
	DNSType              string                `mapstructure:"DNSType"`
	DisableUploadTraffic bool                  `mapstructure:"DisableUploadTraffic"`
	DisableGetRule       bool                  `mapstructure:"DisableGetRule"`
	EnableProxyProtocol  bool                  `mapstructure:"EnableProxyProtocol"`
	EnableFallback       bool                  `mapstructure:"EnableFallback"`
	DisableIVCheck       bool                  `mapstructure:"DisableIVCheck"`
	DisableSniffing      bool                  `mapstructure:"DisableSniffing"`
	AutoSpeedLimitConfig *AutoSpeedLimitConfig `mapstructure:"AutoSpeedLimitConfig"`
	FallBackConfigs      []*FallBackConfig     `mapstructure:"FallBackConfigs"`
}

type AutoSpeedLimitConfig struct {
	Limit         int `mapstructure:"Limit"` // mbps
	WarnTimes     int `mapstructure:"WarnTimes"`
	LimitSpeed    int `mapstructure:"LimitSpeed"`    // mbps
	LimitDuration int `mapstructure:"LimitDuration"` // minute
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}
