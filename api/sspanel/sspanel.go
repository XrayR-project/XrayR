package sspanel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
)

var (
	firstPortRe  = regexp.MustCompile(`(?m)port=(?P<outport>\d+)#?`) // First Port
	secondPortRe = regexp.MustCompile(`(?m)port=\d+#(\d+)`)          // Second Port
	hostRe       = regexp.MustCompile(`(?m)host=([\w\.]+)\|?`)       // Host
)

// APIClient create a api client to the panel.
type APIClient struct {
	client              *resty.Client
	APIHost             string
	NodeID              int
	Key                 string
	NodeType            string
	EnableVless         bool
	EnableXTLS          bool
	SpeedLimit          float64
	DeviceLimit         int
	DisableCustomConfig bool
	LocalRuleList       []api.DetectRule
	LastReportOnline    map[int]int
	access              sync.Mutex
}

// New creat a api instance
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
	client.SetQueryParam("key", apiConfig.Key)
	// Add support for muKey
	client.SetQueryParam("muKey", apiConfig.Key)
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	return &APIClient{
		client:              client,
		NodeID:              apiConfig.NodeID,
		Key:                 apiConfig.Key,
		APIHost:             apiConfig.APIHost,
		NodeType:            apiConfig.NodeType,
		EnableVless:         apiConfig.EnableVless,
		EnableXTLS:          apiConfig.EnableXTLS,
		SpeedLimit:          apiConfig.SpeedLimit,
		DeviceLimit:         apiConfig.DeviceLimit,
		LocalRuleList:       localRuleList,
		DisableCustomConfig: apiConfig.DisableCustomConfig,
		LastReportOnline:    make(map[int]int),
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		//handle errors while opening
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
			return make([]api.DetectRule, 0)
		}

		file.Close()
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
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Ret != 1 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("Ret %s invalid", string(res))
	}
	return response, nil
}

// GetNodeInfo will pull NodeInfo Config from sspanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	// New sspanel API
	disableCustomConfig := c.DisableCustomConfig
	if nodeInfoResponse.Version == "2021.11" && !disableCustomConfig {
		// Check if custom_config is empty
		if configString, err := json.Marshal(nodeInfoResponse.CustomConfig); err != nil || string(configString) == "[]" {
			log.Printf("custom_config is empty! take config from address now.")
			disableCustomConfig = true
		}
	} else {
		disableCustomConfig = true
	}

	if !disableCustomConfig {
		nodeInfo, err = c.ParseSSPanelNodeInfo(nodeInfoResponse)
		if err != nil {
			res, _ := json.Marshal(nodeInfoResponse)
			return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s, \nPlease check the doc of custom_config for help: https://crackair.gitbook.io/xrayr-project/dui-jie-sspanel/sspanel/sspanel_custom_config", string(res), err)
		}
	} else {
		switch c.NodeType {
		case "V2ray":
			nodeInfo, err = c.ParseV2rayNodeResponse(nodeInfoResponse)
		case "Trojan":
			nodeInfo, err = c.ParseTrojanNodeResponse(nodeInfoResponse)
		case "Shadowsocks":
			nodeInfo, err = c.ParseSSNodeResponse(nodeInfoResponse)
		case "Shadowsocks-Plugin":
			nodeInfo, err = c.ParseSSPluginNodeResponse(nodeInfoResponse)
		default:
			return nil, fmt.Errorf("Unsupported Node type: %s", c.NodeType)
		}
	}

	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form sspanel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/mod_mu/users"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]UserResponse)

	if err := json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	userList, err := c.ParseUserListResponse(userListResponse)
	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("Parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ReportNodeStatus reports the node status to the sspanel
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
	systemload := SystemLoad{
		Uptime: strconv.Itoa(nodeStatus.Uptime),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.CPU/100, nodeStatus.CPU/100),
	}

	res, err := c.client.R().
		SetBody(systemload).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

//ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
		if _, ok := reportOnline[user.UID]; ok {
			reportOnline[user.UID]++
		} else {
			reportOnline[user.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	postData := &PostData{Data: data}
	path := fmt.Sprintf("/mod_mu/users/aliveip")
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
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

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/traffic"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
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

// GetNodeRule will pull the audit rule form sspanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	path := "/mod_mu/func/detect_rules"
	res, err := c.client.R().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	ruleListResponse := new([]RuleItem)

	if err := json.Unmarshal(response.Data, ruleListResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(ruleListResponse), err)
	}

	for _, r := range *ruleListResponse {
		ruleList = append(ruleList, api.DetectRule{
			ID:      r.ID,
			Pattern: regexp.MustCompile(r.Content),
		})
	}
	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {

	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
		}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/detectlog"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
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

// ParseV2rayNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseV2rayNodeResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var enableTLS bool
	var path, host, TLStype, transportProtocol, serviceName, HeaderType string
	var header json.RawMessage
	var speedlimit uint64 = 0
	if nodeInfoResponse.RawServerString == "" {
		return nil, fmt.Errorf("No server info in response")
	}
	//nodeInfo.RawServerString = strings.ToLower(nodeInfo.RawServerString)
	serverConf := strings.Split(nodeInfoResponse.RawServerString, ";")
	port, err := strconv.Atoi(serverConf[1])
	if err != nil {
		return nil, err
	}
	alterID, err := strconv.Atoi(serverConf[2])
	if err != nil {
		return nil, err
	}
	// Compatible with more node types config
	for _, value := range serverConf[3:5] {
		switch value {
		case "tls", "xtls":
			if c.EnableXTLS {
				TLStype = "xtls"
			} else {
				TLStype = "tls"
			}
			enableTLS = true
		default:
			if value != "" {
				transportProtocol = value
			}
		}
	}
	extraServerConf := strings.Split(serverConf[5], "|")
	serviceName = ""
	for _, item := range extraServerConf {
		conf := strings.Split(item, "=")
		key := conf[0]
		if key == "" {
			continue
		}
		value := conf[1]
		switch key {
		case "path":
			rawPath := strings.Join(conf[1:], "=") // In case of the path strings contains the "="
			path = rawPath
		case "host":
			host = value
		case "servicename":
			serviceName = value
		case "headertype":
			HeaderType = value
		}
	}
	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	if HeaderType != "" {
		headers := map[string]string{"type": HeaderType}
		header, err = json.Marshal(headers)
	}

	if err != nil {
		return nil, fmt.Errorf("Marshal Header Type %s into config fialed: %s", header, err)
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		AlterID:           alterID,
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		TLSType:           TLStype,
		Path:              path,
		Host:              host,
		EnableVless:       c.EnableVless,
		ServiceName:       serviceName,
		Header:            header,
	}

	return nodeinfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseSSNodeResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var port int = 0
	var speedlimit uint64 = 0
	var method string
	path := "/mod_mu/users"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]UserResponse)

	if err := json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("Unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	// Find the multi-user
	for _, u := range *userListResponse {
		if u.MultiUser > 0 {
			port = u.Port
			method = u.Method
			break
		}
	}
	if port == 0 || method == "" {
		return nil, fmt.Errorf("Cant find the single port multi user")
	}

	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}
	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		TransportProtocol: "tcp",
		CypherMethod:      method,
	}

	return nodeinfo, nil
}

// ParseSSPluginNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseSSPluginNodeResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var enableTLS bool
	var path, host, TLStype, transportProtocol string
	var speedlimit uint64 = 0

	serverConf := strings.Split(nodeInfoResponse.RawServerString, ";")
	port, err := strconv.Atoi(serverConf[1])
	if err != nil {
		return nil, err
	}
	port = port - 1 // Shadowsocks-Plugin requires two ports, one for ss the other for other stream protocol
	if port <= 0 {
		return nil, fmt.Errorf("Shadowsocks-Plugin listen port must bigger than 1")
	}
	// Compatible with more node types config
	for _, value := range serverConf[3:5] {
		switch value {
		case "tls", "xtls":
			if c.EnableXTLS {
				TLStype = "xtls"
			} else {
				TLStype = "tls"
			}
			enableTLS = true
		case "ws":
			transportProtocol = "ws"
		case "obfs":
			transportProtocol = "tcp"
		}
	}

	extraServerConf := strings.Split(serverConf[5], "|")
	for _, item := range extraServerConf {
		conf := strings.Split(item, "=")
		key := conf[0]
		if key == "" {
			continue
		}
		value := conf[1]
		switch key {
		case "path":
			rawPath := strings.Join(conf[1:], "=") // In case of the path strings contains the "="
			path = rawPath
		case "host":
			host = value
		}
	}
	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		TLSType:           TLStype,
		Path:              path,
		Host:              host,
	}

	return nodeinfo, nil
}

// ParseTrojanNodeResponse parse the response for the given nodeinfor format
func (c *APIClient) ParseTrojanNodeResponse(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	// 域名或IP;port=连接端口#偏移端口|host=xx
	// gz.aaa.com;port=443#12345|host=hk.aaa.com
	var p, TLSType, host, outsidePort, insidePort, transportProtocol, serviceName string
	var speedlimit uint64 = 0
	if c.EnableXTLS {
		TLSType = "xtls"
	} else {
		TLSType = "tls"
	}

	if nodeInfoResponse.RawServerString == "" {
		return nil, fmt.Errorf("No server info in response")
	}
	if result := firstPortRe.FindStringSubmatch(nodeInfoResponse.RawServerString); len(result) > 1 {
		outsidePort = result[1]
	}
	if result := secondPortRe.FindStringSubmatch(nodeInfoResponse.RawServerString); len(result) > 1 {
		insidePort = result[1]
	}
	if result := hostRe.FindStringSubmatch(nodeInfoResponse.RawServerString); len(result) > 1 {
		host = result[1]
	}

	if insidePort != "" {
		p = insidePort
	} else {
		p = outsidePort
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}

	serverConf := strings.Split(nodeInfoResponse.RawServerString, ";")
	extraServerConf := strings.Split(serverConf[1], "|")
	transportProtocol = "tcp"
	serviceName = ""
	for _, item := range extraServerConf {
		conf := strings.Split(item, "=")
		key := conf[0]
		if key == "" {
			continue
		}
		value := conf[1]
		switch key {
		case "grpc":
			transportProtocol = "grpc"
		case "servicename":
			serviceName = value
		}
	}

	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}
	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		TransportProtocol: transportProtocol,
		EnableTLS:         true,
		TLSType:           TLSType,
		Host:              host,
		ServiceName:       serviceName,
	}

	return nodeinfo, nil
}

// ParseUserListResponse parse the response for the given nodeinfo format
func (c *APIClient) ParseUserListResponse(userInfoResponse *[]UserResponse) (*[]api.UserInfo, error) {
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var deviceLimit, localDeviceLimit int = 0, 0
	var speedlimit uint64 = 0
	userList := []api.UserInfo{}
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
			speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedlimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList = append(userList, api.UserInfo{
			UID:           user.ID,
			Email:         user.Email,
			UUID:          user.UUID,
			Passwd:        user.Passwd,
			SpeedLimit:    speedlimit,
			DeviceLimit:   deviceLimit,
			Port:          user.Port,
			Method:        user.Method,
			Protocol:      user.Protocol,
			ProtocolParam: user.ProtocolParam,
			Obfs:          user.Obfs,
			ObfsParam:     user.ObfsParam,
		})
	}

	return &userList, nil
}

// ParseSSPanelNodeInfo parse the response for the given nodeinfor format
// Only used for SSPanel version >= 2021.11
func (c *APIClient) ParseSSPanelNodeInfo(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {

	var speedlimit uint64 = 0
	var EnableTLS, EnableVless bool
	var AlterID int = 0
	var TLSType, transportProtocol string

	nodeConfig := new(CustomConfig)
	json.Unmarshal(nodeInfoResponse.CustomConfig, nodeConfig)

	if c.SpeedLimit > 0 {
		speedlimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedlimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	port, err := strconv.Atoi(nodeConfig.OffsetPortNode)
	if err != nil {
		return nil, err
	}

	if c.NodeType == "Shadowsocks" {
		transportProtocol = "tcp"
	}

	if c.NodeType == "V2ray" {
		transportProtocol = nodeConfig.Network
		TLSType = nodeConfig.Security
		if AlterID, err = strconv.Atoi(nodeConfig.AlterID); err != nil {
			return nil, err
		}
		if TLSType == "tls" || TLSType == "xtls" {
			EnableTLS = true
		}
		if nodeConfig.EnableVless == "1" {
			EnableVless = true
		}
	}

	if c.NodeType == "Trojan" {
		EnableTLS = true
		TLSType = "tls"
		if nodeConfig.Grpc == "1" {
			transportProtocol = "grpc"
		} else {
			transportProtocol = "tcp"
		}

		if nodeConfig.EnableXtls == "1" {
			TLSType = "xtls"
		}
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedlimit,
		AlterID:           AlterID,
		TransportProtocol: transportProtocol,
		Host:              nodeConfig.Host,
		Path:              nodeConfig.Path,
		EnableTLS:         EnableTLS,
		TLSType:           TLSType,
		EnableVless:       EnableVless,
		CypherMethod:      nodeConfig.MuEncryption,
		ServiceName:       nodeConfig.Servicename,
		Header:            nodeConfig.Header,
	}

	return nodeinfo, nil
}
