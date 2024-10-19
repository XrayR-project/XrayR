package gov2panel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/gclient"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

// APIClient API config
type APIClient struct {
	ctx                 context.Context
	APIHost             string
	NodeID              int
	Key                 string
	NodeType            string
	EnableVless         bool
	VlessFlow           string
	Timeout             int
	SpeedLimit          float64
	DeviceLimit         int
	RuleListPath        string
	DisableCustomConfig bool

	LocalRuleList []api.DetectRule
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {

	//https://goframe.org/pages/viewpage.action?pageId=1114381

	apiClient := &APIClient{
		ctx:                 context.Background(),
		APIHost:             apiConfig.APIHost,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		VlessFlow:           apiConfig.VlessFlow,
		Timeout:             apiConfig.Timeout,
		DeviceLimit:         apiConfig.DeviceLimit,
		RuleListPath:        apiConfig.RuleListPath,
		DisableCustomConfig: apiConfig.DisableCustomConfig,

		LocalRuleList: readLocalRuleList(apiConfig.RuleListPath), //加载本地路由规则
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

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

		file.Close()
	}

	return LocalRuleList
}

func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {

	apiPath := "/api/server/config"
	reslutJson, err := c.sendRequest(
		nil,
		"POST",
		apiPath,
		g.Map{})
	if err != nil {
		return nil, err
	}

	if reslutJson.Get("data").String() == "" {
		return nil, errors.New("gov2panel node config data is null")
	}

	if reslutJson.Get("data.port").Int() == 0 {
		return nil, errors.New("server port must > 0")
	}

	nodeInfo = new(api.NodeInfo)
	err = reslutJson.Get("data").Scan(nodeInfo)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: \nError: %v", err)
	}

	routes := make([]route, 0)
	err = reslutJson.Get("data.routes").Scan(&routes)
	if err != nil {
		return nil, fmt.Errorf("parse node routes failed: \nError: %v", err)
	}

	nodeInfo.NodeType = c.NodeType
	nodeInfo.NodeID = c.NodeID
	nodeInfo.EnableVless = c.EnableVless
	nodeInfo.VlessFlow = c.VlessFlow

	nodeInfo.AlterID = 0

	nodeInfo.NameServerConfig = parseDNSConfig(routes)

	return nodeInfo, nil

}

func parseDNSConfig(routes []route) (nameServerList []*conf.NameServerConfig) {

	nameServerList = make([]*conf.NameServerConfig, 0)
	for i := range routes {
		if routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(routes[i].ActionValue)},
				Domains: routes[i].Match,
			})
		}
	}

	return
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {

	apiPath := "/api/server/user"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	reslutJson, err := c.sendRequest(
		nil,
		"GET",
		apiPath,
		g.Map{})
	if err != nil {
		return nil, err
	}

	var users []*user
	reslutJson.Get("data.users").Scan(&users)

	userList := make([]api.UserInfo, len(users))
	for i := 0; i < len(users); i++ {
		u := api.UserInfo{
			UID:  users[i].Id,
			UUID: users[i].Uuid,
		}

		// Support 1.7.1 speed limit
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(users[i].SpeedLimit * 1000000 / 8)
		}

		u.DeviceLimit = c.DeviceLimit // todo waiting v2board send configuration
		u.Email = u.UUID + "@gov2panel.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}

	return &userList, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUser *[]api.OnlineUser) (err error) {
	return
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) (err error) {
	apiPath := "/api/server/push"
	reslutJson, err := c.sendRequest(
		nil,
		"POST",
		apiPath,
		g.Map{
			"data": userTraffic,
		})
	if err != nil {
		return err
	}

	if reslutJson.Get("code").Int() != 0 {
		return errors.New(reslutJson.Get("message").String())
	}

	return
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList

	apiPath := "/api/server/config"
	reslutJson, err := c.sendRequest(
		nil,
		"POST",
		apiPath,
		g.Map{})
	if err != nil {
		return nil, err
	}

	routes := make([]route, 0)
	err = reslutJson.Get("data.routes").Scan(&routes)
	if err != nil {
		return nil, fmt.Errorf("parse node routes failed: \nError: %v", err)
	}

	for i := range routes {
		if routes[i].Action == "block" {
			for _, v := range routes[i].Match {
				ruleList = append(ruleList, api.DetectRule{
					ID:      i,
					Pattern: regexp.MustCompile(v),
				})
			}

		}
	}

	return &ruleList, nil

}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return
}

func (c *APIClient) Debug() {

}

// request 统一请求接口
func (c *APIClient) sendRequest(headerM map[string]string, method string, url string, data g.Map) (reslutJson *gjson.Json, err error) {
	url = c.APIHost + url

	client := gclient.New()

	var gResponse *gclient.Response

	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second) //方法用于设置当前请求超时时间
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.Retry(3, 10*time.Second) //方法用于设置请求失败时重连次数和重连间隔。

	client.SetHeaderMap(headerM)
	client.SetHeader("Content-Type", "application/json")

	data["token"] = c.Key
	data["node_id"] = c.NodeID

	switch method {
	case "GET":
		gResponse, err = client.Get(c.ctx, url, data)
	case "POST":
		gResponse, err = client.Post(c.ctx, url, data)
	default:
		err = fmt.Errorf("unsupported method: %s", method)
		return
	}

	if err != nil {
		return
	}
	defer gResponse.Close()

	reslutJson = gjson.New(gResponse.ReadAllString())
	if reslutJson == nil {
		err = fmt.Errorf("http reslut to json, err : %s", gResponse.ReadAllString())
	}
	if reslutJson.Get("code").Int() != 0 {
		err = errors.New(reslutJson.Get("message").String())
		return
	}

	return
}
