package pmpanel

import "encoding/json"

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	Class           int     `json:"clazz"`
	SpeedLimit      float64 `json:"speedlimit"`
	Method          string  `json:"method"`
	TrafficRate     float64 `json:"trafficRate"`
	RawServerString string  `json:"outServer"`
	Port            int     `json:"outPort"`
	AlterId         int     `json:"alterId"`
	Network         string  `json:"network"`
	Security        string  `json:"security"`
	Host            string  `json:"host"`
	Path            string  `json:"path"`
	Grpc            bool    `json:"grpc"`
	Sni             string  `json:sni`
}

// UserResponse is the response of user
type UserResponse struct {
	ID          int     `json:"id"`
	Passwd      string  `json:"passwd"`
	SpeedLimit  float64 `json:"nodeSpeedlimit"`
	DeviceLimit int     `json:"nodeConnector"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Type    string      `json:"type"`
	NodeId  int         `json:"nodeId"`
	Users   interface{} `json:"users"`
	Onlines interface{} `json:"onlines"`
}

// SystemLoad is the data structure of systemload
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
	UID      int    `json:"id"`
	Upload   int64  `json:"up"`
	Download int64  `json:"down"`
	Ip       string `json:"ip"`
}

type RuleItem struct {
	ID      int    `json:"id"`
	Content string `json:"regex"`
}

type IllegalItem struct {
	ID  int `json:"list_id"`
	UID int `json:"user_id"`
}
