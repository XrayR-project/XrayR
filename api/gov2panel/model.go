package gov2panel

import "encoding/json"

type serverConfig struct {
	v2ray
	shadowsocks
	//---
	Routes []route          `json:"routes"`
	Header *json.RawMessage `json:"header"`
}

type v2ray struct {
	Port string `json:"port"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	Sni  string `json:"sni"`
	Alpn string `json:"alpn"`
}

type shadowsocks struct {
	Encryption   string `json:"encryption"`
	Obfs         string `json:"obfs"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`
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
