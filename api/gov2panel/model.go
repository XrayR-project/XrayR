package gov2panel

type user struct {
	Id         int    `json:"id"`
	Uuid       string `json:"uuid"`
	SpeedLimit int    `json:"speed_limit"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}
