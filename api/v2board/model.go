package v2board

type UserTraffic struct {
	UID   int `json:"user_id"`
	Upload   int64  `json:"u"`
	Download int64  `json:"d"`
}
