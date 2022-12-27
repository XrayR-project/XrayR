package newV2board

import (
	"encoding/json"
)

type serverConfig struct {
	ServerPort int `json:"server_port"`
	BaseConfig struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`
	Routes []route `json:"routes"`

	// shadowsocks
	Cipher       string `json:"cipher"`
	Obfs         string `json:"obfs"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`

	// v2ray
	Network         string `json:"network"`
	NetworkSettings struct {
		Path        string           `json:"path"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
	} `json:"networkSettings"`
	Tls int `json:"tls"`

	// trojan
	Host       string `json:"host"`
	ServerName string `json:"server_name"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type user struct {
	Id         int    `json:"id"`
	Uuid       string `json:"uuid"`
	SpeedLimit int    `json:"speed_limit"`
}
