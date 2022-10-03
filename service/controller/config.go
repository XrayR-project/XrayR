package controller

type Config struct {
	ListenIP             string                `mapstructure:"ListenIP"`
	SendIP               string                `mapstructure:"SendIP"`
	UpdatePeriodic       int                   `mapstructure:"UpdatePeriodic"`
	CertConfig           *CertConfig           `mapstructure:"CertConfig"`
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

type CertConfig struct {
	CertMode         string            `mapstructure:"CertMode"` // none, file, http, dns
	RejectUnknownSni bool              `mapstructure:"RejectUnknownSni"`
	CertDomain       string            `mapstructure:"CertDomain"`
	CertFile         string            `mapstructure:"CertFile"`
	KeyFile          string            `mapstructure:"KeyFile"`
	Provider         string            `mapstructure:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email            string            `mapstructure:"Email"`
	DNSEnv           map[string]string `mapstructure:"DNSEnv"`
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}
