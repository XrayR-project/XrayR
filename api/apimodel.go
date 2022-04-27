package api

import (
	"encoding/json"
	"regexp"
)

// API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	NodeType            string  `mapstructure:"NodeType"`
	EnableVless         bool    `mapstructure:"EnableVless"`
	EnableXTLS          bool    `mapstructure:"EnableXTLS"`
	Timeout             int     `mapstructure:"Timeout"`
	SpeedLimit          float64 `mapstructure:"SpeedLimit"`
	DeviceLimit         int     `mapstructure:"DeviceLimit"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
	DisableCustomConfig bool    `mapstructure:"DisableCustomConfig"`
}

// Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime int
}

type NodeInfo struct {
	NodeType          string // Must be V2ray, Trojan, and Shadowsocks
	NodeID            int
	Port              int
	SpeedLimit        uint64 // Bps
	AlterID           int
	TransportProtocol string
	FakeType          string
	Host              string
	Path              string
	EnableTLS         bool
	TLSType           string
	EnableVless       bool
	CypherMethod      string
	ServiceName       string
	Header            json.RawMessage
}

type UserInfo struct {
	UID           int
	Email         string
	Passwd        string
	Port          int
	Method        string
	SpeedLimit    uint64 // Bps
	DeviceLimit   int
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
	UUID          string
	AlterID       int
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
	NodeType string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}
