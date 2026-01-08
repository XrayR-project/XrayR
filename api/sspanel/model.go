package sspanel

import "encoding/json"

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	Group           int             `json:"node_group"`
	Class           int             `json:"node_class"`
	SpeedLimit      float64         `json:"node_speedlimit"`
	TrafficRate     float64         `json:"traffic_rate"`
	Sort            int             `json:"sort"`
	RawServerString string          `json:"server"`
	Type            string          `json:"type"`
	CustomConfig    json.RawMessage `json:"custom_config"`
	Version         string          `json:"version"`
}

type CustomConfig struct {
	OffsetPortNode        string          `json:"offset_port_node"`
	OffsetPortUser        string          `json:"offset_port_user"`
	Host                  string          `json:"host"`
	Method                string          `json:"method"`
	ServerKey             string          `json:"server_key"`
	TLS                   string          `json:"tls"`
	EnableVless           string          `json:"enable_vless"`
	Network               string          `json:"network"`
	Security              string          `json:"security"`
	Path                  string          `json:"path"`
	VerifyCert            bool            `json:"verify_cert"`
	Obfs                  string          `json:"obfs"`
	Header                json.RawMessage `json:"header"`
	AllowInsecure         string          `json:"allow_insecure"`
	Servicename           string          `json:"servicename"`
	EnableXtls            string          `json:"enable_xtls"`
	Flow                  string          `json:"flow"`
	EnableREALITY         bool            `json:"enable_reality"`
	RealityOpts           *REALITYConfig  `json:"reality-opts"`
	ObfsPassword          string          `json:"obfs_password"`
	UpMbps                string          `json:"up_mbps"`
	DownMbps              string          `json:"down_mbps"`
	ServerName            string          `json:"server_name"`
	Sni                   string          `json:"sni"`
	Alpn                  []string        `json:"alpn"`
	Fingerprint           string          `json:"fingerprint"`
	IgnoreClientBandwidth bool            `json:"ignore_client_bandwidth"`
	PaddingScheme         []string        `json:"padding_scheme"`
	// Hysteria2 port hopping fields kept raw to allow loose types from panel JSON
	PortHopEnableRaw   json.RawMessage `json:"port_hop_enable"`
	PortHopPortsRaw    json.RawMessage `json:"port_hop_ports"`
	PortHopIntervalRaw json.RawMessage `json:"port_hop_interval"`
	// TUIC-specific transport tuning
	CongestionControl string `json:"congestion_control"`
	UDPRelayMode      string `json:"udp_relay_mode"`
	ZeroRTTHandshake  string `json:"zero_rtt_handshake"`
	Heartbeat         string `json:"heartbeat"`
	// Per-node proxy protocol control
	EnableProxyProtocol bool   `json:"enable_proxy_protocol"`
	ProxyProtocolVer    uint64 `json:"proxy_protocol_ver"`
}

// UserResponse is the response of user
type UserResponse struct {
	ID          int     `json:"id"`
	Passwd      string  `json:"passwd"`
	Port        uint32  `json:"port"`
	Method      string  `json:"method"`
	SpeedLimit  float64 `json:"node_speedlimit"`
	DeviceLimit int     `json:"node_iplimit"`
	UUID        string  `json:"uuid"`
	AliveIP     int     `json:"alive_ip"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// SystemLoad is the data structure of system load
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	UID int    `json:"user_id"`
	IP  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type UserTraffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type RuleItem struct {
	ID      int    `json:"id"`
	Content string `json:"regex"`
}

type IllegalItem struct {
	ID  int    `json:"list_id"`
	UID int    `json:"user_id"`
	IP  string `json:"ip,omitempty"`
}

type REALITYConfig struct {
	Dest             string   `json:"dest,omitempty"`
	ProxyProtocolVer uint64   `json:"proxy_protocol_ver,omitempty"`
	ServerNames      []string `json:"server_names,omitempty"`
	PrivateKey       string   `json:"private_key,omitempty"`
	MinClientVer     string   `json:"min_client_ver,omitempty"`
	MaxClientVer     string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff      uint64   `json:"max_time_diff,omitempty"`
	ShortIds         []string `json:"short_ids,omitempty"`
}
