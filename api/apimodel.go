package api

import (
	"encoding/json"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

const (
	UserNotModified = "users not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
)

// Config API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	NodeType            string  `mapstructure:"NodeType"`
	EnableVless         bool    `mapstructure:"EnableVless"`
	VlessFlow           string  `mapstructure:"VlessFlow"`
	Timeout             int     `mapstructure:"Timeout"`
	SpeedLimit          float64 `mapstructure:"SpeedLimit"`
	DeviceLimit         int     `mapstructure:"DeviceLimit"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
	DisableCustomConfig bool    `mapstructure:"DisableCustomConfig"`
}

// NodeStatus Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	AcceptProxyProtocol bool
	Authority           string
	NodeType            string // V2ray/Vmess, VLESS, Trojan, Shadowsocks, Hysteria2, AnyTLS, Tuic, Socks, HTTP
	NodeID              int
	Port                uint32
	SpeedLimit          uint64 // Bps
	AlterID             uint16
	TransportProtocol   string
	FakeType            string
	Host                string
	SNI                 string
	Path                string
	EnableTLS           bool
	EnableSniffing      bool
	RouteOnly           bool
	EnableVless         bool
	VlessFlow           string
	CypherMethod        string
	ServerKey           string
	ServiceName         string
	Method              string
	Header              json.RawMessage
	HttpHeaders         map[string]*conf.StringList
	Headers             map[string]string
	NameServerConfig    []*conf.NameServerConfig
	EnableREALITY       bool
	REALITYConfig       *REALITYConfig
	Show                bool
	EnableTFO           bool
	Dest                string
	ProxyProtocolVer    uint64
	ServerNames         []string
	PrivateKey          string
	MinClientVer        string
	MaxClientVer        string
	MaxTimeDiff         uint64
	ShortIds            []string
	Xver                uint64
	Flow                string
	Security            string
	Key                 string
	RejectUnknownSni    bool
	Hysteria2Config     *Hysteria2Config
	AnyTLSConfig        *AnyTLSConfig
	TuicConfig          *TuicConfig

	// XHTTP (SplitHTTP) bypass CDN fields — new in Xray-core v26.2+
	XHTTPMode             string          // auto, packet-up, stream-up, stream-one
	XHTTPExtra            json.RawMessage // raw "extra" JSON for full override
	XPaddingBytes         *[2]int32       // [from, to] range for xPaddingBytes
	XPaddingObfsMode      bool            // xPaddingObfsMode
	XPaddingKey           string          // xPaddingKey
	XPaddingHeader        string          // xPaddingHeader
	XPaddingPlacement     string          // queryInHeader, cookie, header, query
	XPaddingMethod        string          // repeat-x, tokenish
	UplinkHTTPMethod      string          // POST, GET
	SessionPlacement      string          // path, cookie, header, query
	SessionKey            string          // key for session placement
	SeqPlacement          string          // path, cookie, header, query
	SeqKey                string          // key for seq placement
	UplinkDataPlacement   string          // body, cookie, header
	UplinkDataKey         string          // key for uplink data placement
	UplinkChunkSize       uint32          // chunk size for non-body uplink
	NoGRPCHeader          bool            // disable gRPC header
	NoSSEHeader           bool            // disable SSE header
	ScMaxEachPostBytes    *[2]int32       // [from, to] range
	ScMinPostsIntervalMs  *[2]int32       // [from, to] range
	ScMaxBufferedPosts    int64           // max buffered posts
	ScStreamUpServerSecs  *[2]int32       // [from, to] range
	XmuxMaxConcurrency    *[2]int32       // [from, to] range
	XmuxMaxConnections    *[2]int32       // [from, to] range
	XmuxCMaxReuseTimes    *[2]int32       // [from, to] range
	XmuxHMaxRequestTimes  *[2]int32       // [from, to] range
	XmuxHMaxReusableSecs  *[2]int32       // [from, to] range
	XmuxHKeepAlivePeriod  int64           // keep alive period
	XHTTPDownloadSettings json.RawMessage // downloadSettings raw JSON
}

type UserInfo struct {
	UID         int
	Email       string
	UUID        string
	Passwd      string
	Port        uint32
	AlterID     uint16
	Method      string
	SpeedLimit  uint64 // Bps
	DeviceLimit int
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
	IP     string
}

// XrayRCertConfig carries optional panel-provided certificate settings
// (e.g., DNS provider, ACME email, and DNS-01 environment variables).
type XrayRCertConfig struct {
	Provider string            `json:"provider"`
	Email    string            `json:"email"`
	DNSEnv   map[string]string `json:"dns_env"`
}

type Hysteria2Config struct {
	Obfs                  string
	ObfsPassword          string
	UpMbps                int
	DownMbps              int
	IgnoreClientBandwidth bool
	PortHopEnabled        bool
	PortHopPorts          string
}

type AnyTLSConfig struct {
	PaddingScheme []string
}

type TuicConfig struct {
	CongestionControl string
	UDPRelayMode      string
	ZeroRTTHandshake  bool
	Heartbeat         int
	AuthTimeout       int
	ALPN              []string
}

type REALITYConfig struct {
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
}
