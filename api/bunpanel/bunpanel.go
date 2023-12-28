package bunpanel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/XrayR-project/XrayR/api"
)

type APIClient struct {
	client           *resty.Client
	APIHost          string
	NodeID           int
	Key              string
	NodeType         string
	EnableVless      bool
	VlessFlow        string
	SpeedLimit       float64
	DeviceLimit      int
	LocalRuleList    []api.DetectRule
	LastReportOnline map[int]int
	access           sync.Mutex
	eTags            map[string]string
}

// ReportIllegal implements api.API.
func (*APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}

// ReportNodeStatus implements api.API.
func (*APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// GetNodeRule implements api.API.
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	return &ruleList, nil
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
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"serverId": strconv.Itoa(apiConfig.NodeID),
		"nodeType": strings.ToLower(apiConfig.NodeType),
		"token":    apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
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
		defer file.Close()
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

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.StatusCode != 200 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("statusCode %s invalid", string(res))
	}
	return response, nil
}

func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/v2/server/%d/get", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(Server)

	if err := json.Unmarshal(response.Datas, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	nodeInfo, err = c.ParseNodeInfo(nodeInfoResponse)
	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s, \nPlease check the doc of custom_config for help: https://xrayr-project.github.io/XrayR-doc/dui-jie-sspanel/sspanel/sspanel_custom_config", string(res), err)
	}

	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/v2/user/get"
	res, err := c.client.R().
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["users"]).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]User)

	if err := json.Unmarshal(response.Datas, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	userList, err := c.ParseUserListResponse(userListResponse)
	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("parse user list failed: %s", string(res))
	}
	return userList, nil
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		reportOnline[user.UID]++
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	postData := &PostData{Data: data}
	path := "/v2/user/online/create"
	res, err := c.client.R().
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := "/v2/user/data-usage/create"
	res, err := c.client.R().
		SetQueryParam("serverId", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) ParseUserListResponse(userInfoResponse *[]User) (*[]api.UserInfo, error) {
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var deviceLimit, localDeviceLimit = 0, 0
	var speedLimit uint64 = 0
	var userList []api.UserInfo
	for _, user := range *userInfoResponse {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		// If there is still device available, add the user
		if deviceLimit > 0 && user.AliveIP > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.ID]; ok {
				lastOnline = v
			}
			// If there are any available device.
			if localDeviceLimit = deviceLimit - user.AliveIP + lastOnline; localDeviceLimit > 0 {
				deviceLimit = localDeviceLimit
				// If this backend server has reported any user in the last reporting period.
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
				// Remove this user.
			} else {
				continue
			}
		}

		if c.SpeedLimit > 0 {
			speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedLimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList = append(userList, api.UserInfo{
			UID:         user.ID,
			UUID:        user.UUID,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
			Passwd:      user.UUID,
			Email:       user.UUID + "@bunpanel.user",
		})
	}

	return &userList, nil
}

func (c *APIClient) ParseNodeInfo(nodeInfoResponse *Server) (*api.NodeInfo, error) {
	var (
		speedLimit                            uint64 = 0
		enableTLS, enableVless, enableREALITY bool
		alterID                               uint16 = 0
		tlsType, transportProtocol            string
	)

	nodeConfig := nodeInfoResponse
	port := uint32(nodeConfig.Port)

	switch c.NodeType {
	case "Shadowsocks":
		transportProtocol = "tcp"
	case "V2ray":
		transportProtocol = nodeConfig.Network
		tlsType = nodeConfig.Security

		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}
		if tlsType == "reality" {
			enableREALITY = true
			enableVless = true
		}
	case "Trojan":
		enableTLS = true
		tlsType = "tls"
		transportProtocol = "tcp"
	}

	// parse reality config
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealitySettings != nil {
		r := new(RealitySettings)
		json.Unmarshal(nodeConfig.RealitySettings, r)
		realityConfig = &api.REALITYConfig{
			Dest:             r.Dest,
			ProxyProtocolVer: r.ProxyProtocolVer,
			ServerNames:      r.ServerNames,
			PrivateKey:       r.PrivateKey,
			MinClientVer:     r.MinClientVer,
			MaxClientVer:     r.MaxClientVer,
			MaxTimeDiff:      r.MaxTimeDiff,
			ShortIds:         r.ShortIds,
		}
	}
	wsConfig := new(WsSettings)
	if nodeConfig.WsSettings != nil {
		json.Unmarshal(nodeConfig.WsSettings, wsConfig)
	}

	grpcConfig := new(GrpcSettigns)
	if nodeConfig.GrpcSettings != nil {
		json.Unmarshal(nodeConfig.GrpcSettings, grpcConfig)
	}

	tcpConfig := new(TcpSettings)
	if nodeConfig.TcpSettings != nil {
		json.Unmarshal(nodeConfig.TcpSettings, tcpConfig)
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedLimit,
		AlterID:           alterID,
		TransportProtocol: transportProtocol,
		Host:              wsConfig.Headers.Host,
		Path:              wsConfig.Path,
		EnableTLS:         enableTLS,
		EnableVless:       enableVless,
		VlessFlow:         nodeConfig.Flow,
		CypherMethod:      nodeConfig.Method,
		ServiceName:       grpcConfig.ServiceName,
		Header:            tcpConfig.Header,
		EnableREALITY:     enableREALITY,
		REALITYConfig:     realityConfig,
	}

	return nodeInfo, nil
}
