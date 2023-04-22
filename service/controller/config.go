package controller

import (
	"github.com/XrayR-project/XrayR/common/limiter"
	"github.com/XrayR-project/XrayR/common/mylego"
)

type Config struct {
	ListenIP                string                           `mapstructure:"ListenIP"`
	SendIP                  string                           `mapstructure:"SendIP"`
	UpdatePeriodic          int                              `mapstructure:"UpdatePeriodic"`
	CertConfig              *mylego.CertConfig               `mapstructure:"CertConfig"`
	EnableDNS               bool                             `mapstructure:"EnableDNS"`
	DNSType                 string                           `mapstructure:"DNSType"`
	DisableUploadTraffic    bool                             `mapstructure:"DisableUploadTraffic"`
	DisableGetRule          bool                             `mapstructure:"DisableGetRule"`
	EnableProxyProtocol     bool                             `mapstructure:"EnableProxyProtocol"`
	EnableFallback          bool                             `mapstructure:"EnableFallback"`
	DisableIVCheck          bool                             `mapstructure:"DisableIVCheck"`
	DisableSniffing         bool                             `mapstructure:"DisableSniffing"`
	AutoSpeedLimitConfig    *AutoSpeedLimitConfig            `mapstructure:"AutoSpeedLimitConfig"`
	GlobalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
	FallBackConfigs         []*FallBackConfig                `mapstructure:"FallBackConfigs"`
	EnableREALITY           bool                             `mapstructure:"EnableREALITY"`
	REALITYConfigs          *REALITYConfig                   `mapstructure:"REALITYConfigs"`
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

type REALITYConfig struct {
	Show             bool     `mapstructure:"Show"`
	Dest             string   `mapstructure:"Dest"`
	ProxyProtocolVer uint64   `mapstructure:"ProxyProtocolVer"`
	ServerNames      []string `mapstructure:"ServerNames"`
	PrivateKey       string   `mapstructure:"PrivateKey"`
	MinClientVer     string   `mapstructure:"MinClientVer"`
	MaxClientVer     string   `mapstructure:"MaxClientVer"`
	MaxTimeDiff      uint64   `mapstructure:"MaxTimeDiff"`
	ShortIds         []string `mapstructure:"ShortIds"`
}
