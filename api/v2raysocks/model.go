package v2raysocks

type UserTraffic struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type NodeStatus struct {
	CPU    string `json:"cpu"`
	Mem    string `json:"mem"`
	Net    string `json:"net"`
	Disk   string `json:"disk"`
	Uptime int    `json:"uptime"`
}

type NodeOnline struct {
	UID int    `json:"uid"`
	IP  string `json:"ip"`
}

type IllegalItem struct {
	UID int `json:"uid"`
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