package airgo

import "github.com/XrayR-project/XrayR/api"

type NodeInfoResponse struct {
	ID             int64  `json:"id"`
	NodeSpeedlimit int64  `json:"node_speedlimit"`
	TrafficRate    int64  `json:"traffic_rate"`
	NodeType       string `json:"node_type"`
	Remarks        string `json:"remarks"`
	Address        string `json:"address"`
	Port           int64  `json:"port"`
	Scy            string `json:"scy"`
	ServerKey      string `json:"server_key"`
	Aid            int64  `json:"aid"`
	VlessFlow      string `json:"flow"`
	Network        string `json:"network"`
	Type           string `json:"type"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	GrpcMode       string `json:"mode"`
	ServiceName    string `json:"service_name"`
	Security       string `json:"security"`
	Sni            string `json:"sni"`
	Fingerprint    string `json:"fp"`
	Alpn           string `json:"alpn"`
	Dest           string `json:"dest"`
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"pbk"`
	ShortId        string `json:"sid"`
	SpiderX        string `json:"spx"`
}

type UserResponse struct {
	ID       int64  `json:"id"`
	UUID     string `json:"uuid"`
	Passwd   string `json:"passwd"`
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
