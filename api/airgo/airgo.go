package airgo

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
	"log"
	"os"
	"regexp"

	"time"
)

type APIClient struct {
	client              *resty.Client
	APIHost             string
	NodeID              int
	Key                 string
	NodeType            string
	EnableVless         bool
	VlessFlow           string
	SpeedLimit          float64
	DeviceLimit         int
	DisableCustomConfig bool
	LocalRuleList       []api.DetectRule
	eTags               map[string]string
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParam("key", apiConfig.Key)
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	return &APIClient{
		client:              client,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		APIHost:             apiConfig.APIHost,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		VlessFlow:           apiConfig.VlessFlow,
		SpeedLimit:          apiConfig.SpeedLimit,
		DeviceLimit:         apiConfig.DeviceLimit,
		LocalRuleList:       localRuleList,
		DisableCustomConfig: apiConfig.DisableCustomConfig,
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)
		defer file.Close()
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}
		fileScanner := bufio.NewScanner(file)
		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}
	return LocalRuleList
}

func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	path := "/api/airgo/node/getNodeInfo"
	res, err := c.client.R().
		SetQueryParams(map[string]string{
			"id": fmt.Sprintf("%d", c.NodeID),
		}).
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("Etag")
	}
	var nodeInfoResponse NodeInfoResponse
	json.Unmarshal(res.Body(), &nodeInfoResponse)
	nodeInfo, err := c.ParseAirGoNodeInfo(&nodeInfoResponse)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}
	return nodeInfo, nil
}
func (c *APIClient) ParseAirGoNodeInfo(n *NodeInfoResponse) (*api.NodeInfo, error) {
	var nodeInfo api.NodeInfo
	var speedLimit uint64
	var enableTLS bool = true
	var enableREALITY bool = false
	var realityConfig = &api.REALITYConfig{}
	if n.Security == "none" || n.Security == "" {
		enableTLS = false
	}
	if n.Security == "reality" {
		enableREALITY = true
		realityConfig = &api.REALITYConfig{
			Dest:             n.Dest,
			ProxyProtocolVer: 0,
			ServerNames:      []string{n.Sni},
			PrivateKey:       n.PrivateKey,
			MinClientVer:     "",
			MaxClientVer:     "",
			MaxTimeDiff:      0,
			ShortIds:         []string{"", "0123456789abcdef"},
		}
	}
	if n.NodeSpeedlimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((n.NodeSpeedlimit * 1000000) / 8)
	}
	switch n.NodeType {
	case "vless", "Vless":
		nodeInfo = api.NodeInfo{
			EnableVless: true,
			VlessFlow:   n.VlessFlow,
			NodeType:    c.NodeType,
			NodeID:      c.NodeID,
			Port:        uint32(n.Port),
			SpeedLimit:  speedLimit,
			//AlterID:           0,
			TransportProtocol: n.Network,
			EnableTLS:         enableTLS,
			Path:              n.Path,
			Host:              n.Host,
			//CypherMethod:      n.Scy,
			ServiceName:   n.ServiceName,
			EnableREALITY: enableREALITY,
			REALITYConfig: realityConfig,
		}
	case "vmess", "Vmess":
		nodeInfo = api.NodeInfo{
			VlessFlow:         n.VlessFlow,
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			SpeedLimit:        speedLimit,
			AlterID:           0,
			TransportProtocol: n.Network,
			EnableTLS:         enableTLS,
			Path:              n.Path,
			Host:              n.Host,
			//CypherMethod:      n.Scy,
			ServiceName:   n.ServiceName,
			EnableREALITY: enableREALITY,
		}
	case "Shadowsocks", "shadowsocks":
		nodeInfo = api.NodeInfo{
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			SpeedLimit:        speedLimit,
			TransportProtocol: "tcp",
			CypherMethod:      n.Scy,
			ServerKey:         n.ServerKey,
		}
	case "Trojan", "trojan":
		nodeInfo = api.NodeInfo{
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			TransportProtocol: "tcp",
			EnableTLS:         true,
			Host:              n.Host,
			ServiceName:       n.ServiceName,
		}
	}
	return &nodeInfo, nil
}
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := "/api/airgo/node/reportNodeStatus"
	var nodeStatusRequest = NodeStatusRequest{
		ID:     c.NodeID,
		CPU:    nodeStatus.CPU,
		Mem:    nodeStatus.Mem,
		Disk:   nodeStatus.Disk,
		Uptime: nodeStatus.Uptime,
	}
	res, _ := c.client.R().
		SetBody(nodeStatusRequest).
		ForceContentType("application/json").
		Post(path)
	if res.StatusCode() == 200 {
		return nil
	}
	return fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
}

func (c *APIClient) GetUserList() (userList *[]api.UserInfo, err error) {
	path := "/api/airgo/user/getUserlist"
	res, err := c.client.R().
		SetQueryParams(map[string]string{
			"id": fmt.Sprintf("%d", c.NodeID),
		}).
		SetHeader("If-None-Match", c.eTags["userlist"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["userlist"] {
		c.eTags["userlist"] = res.Header().Get("Etag")
	}
	var userResponse []UserResponse
	var userInfo []api.UserInfo
	json.Unmarshal(res.Body(), &userResponse)
	for _, v := range userResponse {
		userInfo = append(userInfo, api.UserInfo{
			UID:    int(v.ID),
			UUID:   v.UUID,
			Email:  v.UserName,
			Passwd: v.Passwd,
		})
	}
	return &userInfo, nil
}
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) (err error) {
	path := "/api/airgo/user/reportUserTraffic"
	var userTrafficRequest = UserTrafficRequest{
		ID:          c.NodeID,
		UserTraffic: *userTraffic,
	}
	res, _ := c.client.R().
		SetBody(userTrafficRequest).
		ForceContentType("application/json").
		Post(path)
	if res.StatusCode() == 200 {
		return nil
	}
	return fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)

}
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) (err error) {
	return nil
}
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{}
}
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	return &ruleList, nil
}
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}
func (c *APIClient) Debug() {}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}
