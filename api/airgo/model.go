package airgo

import "github.com/XrayR-project/XrayR/api"

type NodeInfoResponse struct {
	ID             int64  `json:"id"`
	NodeSpeedlimit int64  `json:"node_speedlimit"` //节点限速/Mbps
	TrafficRate    int64  `json:"traffic_rate"`    //倍率
	NodeType       string `json:"node_type"`       //节点类型 vless,vmess,trojan
	Remarks        string `json:"remarks"`         //别名
	Address        string `json:"address"`         //地址
	Port           int64  `json:"port"`            //端口

	//vmess参数
	Scy string `json:"scy"` //加密方式 auto,none,chacha20-poly1305,aes-128-gcm,zero，vless选择none，否则v2rayng无法启动
	Aid int64  `json:"aid"` //额外ID
	//vless参数
	VlessFlow string `json:"flow"` //流控 none,xtls-rprx-vision,xtls-rprx-vision-udp443

	//传输参数
	Network     string `json:"network"`      //传输协议 tcp,kcp,ws,h2,quic,grpc
	Type        string `json:"type"`         //伪装类型 ws,h2：无    tcp,kcp：none，http    quic：none，srtp，utp，wechat-video，dtls，wireguard
	Host        string `json:"host"`         //伪装域名
	Path        string `json:"path"`         //path
	GrpcMode    string `json:"mode"`         //grpc传输模式 gun，multi
	ServiceName string `json:"service_name"` //

	//传输层安全
	Security    string `json:"security"` //传输层安全类型 none,tls,reality
	Sni         string `json:"sni"`      //
	Fingerprint string `json:"fp"`       //
	Alpn        string `json:"alpn"`     //
	Dest        string `json:"dest"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"pbk"`
	ShortId     string `json:"sid"`
	SpiderX     string `json:"spx"`
}

type UserResponse struct {
	ID       int64  `json:"id"`
	UUID     string `json:"uuid"`
	UserName string `json:"user_name"`
}

type NodeStatusRequest struct {
	ID     int     `json:"id"`
	CPU    float64 `json:"cpu"`
	Mem    float64 `json:"mem"`
	Disk   float64 `json:"disk"`
	Uptime uint64  `json:"uptime"`
}
type UserTrafficRequest struct {
	ID          int               `json:"id"`
	UserTraffic []api.UserTraffic `json:"user_traffic"`
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
