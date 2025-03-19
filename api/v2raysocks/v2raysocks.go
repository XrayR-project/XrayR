package v2raysocks

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"

	"github.com/XrayR-project/XrayR/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	VlessFlow     string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	ConfigResp    *simplejson.Json
	access        sync.Mutex
	eTags         map[string]string
}

// New create an api instance
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
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})

	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id": strconv.Itoa(apiConfig.NodeID),
		"token":   apiConfig.Key,
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

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("ret %s invalid", res.String())
	}
	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	var nodeType string
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless", "Trojan", "Shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["config"]).
		SetQueryParams(map[string]string{
			"act":       "config",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["config"] {
		c.eTags["config"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, "", err)
	c.access.Lock()
	defer c.access.Unlock()
	c.ConfigResp = response
	if err != nil {
		return nil, err
	}

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.ParseV2rayNodeResponse(response)
	case "Trojan":
		nodeInfo, err = c.ParseTrojanNodeResponse(response)
	case "Shadowsocks":
		nodeInfo, err = c.ParseSSNodeResponse(response)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := response.MarshalJSON()
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var nodeType string
	switch c.NodeType {
	case "V2ray", "Vmess", "Vless", "Trojan", "Shadowsocks":
		nodeType = strings.ToLower(c.NodeType)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["user"]).
		SetQueryParams(map[string]string{
			"act":       "user",
			"node_type": nodeType,
		}).
		ForceContentType("application/json").
		Get(c.APIHost)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["user"] {
		c.eTags["user"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, "", err)
	if err != nil {
		return nil, err
	}
	numOfUsers := len(response.Get("data").MustArray())
	userList := make([]api.UserInfo, numOfUsers)
	for i := 0; i < numOfUsers; i++ {
		user := api.UserInfo{}
		user.UID = response.Get("data").GetIndex(i).Get("id").MustInt()
		switch c.NodeType {
		case "Shadowsocks":
			user.Email = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Passwd = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Method = response.Get("data").GetIndex(i).Get("cipher").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "Trojan":
			user.UUID = response.Get("data").GetIndex(i).Get("password").MustString()
			user.Email = response.Get("data").GetIndex(i).Get("password").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "V2ray", "Vmess", "Vless":
			user.UUID = response.Get("data").GetIndex(i).Get("uuid").MustString()
			user.Email = user.UUID + "@x.com"
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		}
		if c.SpeedLimit > 0 {
			user.SpeedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		}

		if c.DeviceLimit > 0 {
			user.DeviceLimit = c.DeviceLimit
		}

		userList[i] = user
	}
	return &userList, nil
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

	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "submit",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList

	// fix: reuse config response
	c.access.Lock()
	defer c.access.Unlock()
	ruleListResponse := c.ConfigResp.Get("routing").Get("rules").GetIndex(1).Get("domain").MustStringArray()
	for i, rule := range ruleListResponse {
		rule = strings.TrimPrefix(rule, "regexp:")
		ruleListItem := api.DetectRule{
			ID:      i,
			Pattern: regexp.MustCompile(rule),
		}
		ruleList = append(ruleList, ruleListItem)
	}
	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	systemload := NodeStatus{
		Uptime: int(nodeStatus.Uptime),
		CPU:    fmt.Sprintf("%d%%", int(nodeStatus.CPU)),
		Mem:    fmt.Sprintf("%d%%", int(nodeStatus.Mem)),
		Disk:   fmt.Sprintf("%d%%", int(nodeStatus.Disk)),
	}

	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "nodestatus",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(systemload).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	data := make([]NodeOnline, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = NodeOnline{UID: user.UID, IP: user.IP}
	}

	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "onlineusers",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			UID: r.UID,
		}
	}

	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetQueryParams(map[string]string{
			"act":       "illegal",
			"node_type": strings.ToLower(c.NodeType),
		}).
		SetBody(data).
		ForceContentType("application/json").
		Post(c.APIHost)
	_, err = c.parseResponse(res, "", err)
	if err != nil {
		return err
	}
	return nil
}

// ParseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseTrojanNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	marshalByte, _ := json.Marshal(tmpInboundInfo[0].(map[string]interface{}))
	inboundInfo, _ := simplejson.NewJson(marshalByte)

	port := uint32(inboundInfo.Get("port").MustUint64())
	host := inboundInfo.Get("streamSettings").Get("tlsSettings").Get("serverName").MustString()

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              host,
	}
	return nodeInfo, nil
}

// ParseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseSSNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	var method, serverPsk string
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	marshalByte, _ := json.Marshal(tmpInboundInfo[0].(map[string]interface{}))
	inboundInfo, _ := simplejson.NewJson(marshalByte)

	port := uint32(inboundInfo.Get("port").MustUint64())
	method = inboundInfo.Get("settings").Get("method").MustString()
	// Shadowsocks 2022
	if C.Contains(shadowaead_2022.List, method) {
		serverPsk = inboundInfo.Get("settings").Get("password").MustString()
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
		CypherMethod:      method,
		ServerKey:         serverPsk,
	}

	return nodeInfo, nil
}

// ParseV2rayNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseV2rayNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	var path, host, serviceName string
	var header json.RawMessage
	var enableTLS bool
	var enableVless bool
	var enableReality bool
	var vlessFlow string

	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	marshalByte, _ := json.Marshal(tmpInboundInfo[0].(map[string]interface{}))
	inboundInfo, _ := simplejson.NewJson(marshalByte)

	port := uint32(inboundInfo.Get("port").MustUint64())
	transportProtocol := inboundInfo.Get("streamSettings").Get("network").MustString()

	switch transportProtocol {
	case "ws":
		path = inboundInfo.Get("streamSettings").Get("wsSettings").Get("path").MustString()
		host = inboundInfo.Get("streamSettings").Get("wsSettings").Get("headers").Get("Host").MustString()
	case "httpupgrade":
		host = inboundInfo.Get("streamSettings").Get("httpupgradeSettings").Get("Host").MustString()
		path = inboundInfo.Get("streamSettings").Get("httpupgradeSettings").Get("path").MustString()
	case "splithttp":
		host = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("Host").MustString()
		path = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("path").MustString()
	case "grpc":
		if data, ok := inboundInfo.Get("streamSettings").Get("grpcSettings").CheckGet("serviceName"); ok {
			serviceName = data.MustString()
		}
	case "tcp":
		if data, ok := inboundInfo.Get("streamSettings").Get("tcpSettings").CheckGet("header"); ok {
			if httpHeader, err := data.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	}

	enableTLS = inboundInfo.Get("streamSettings").Get("security").MustString() == "tls"
	enableVless = inboundInfo.Get("protocol").MustString() == "vless"
	enableReality = inboundInfo.Get("streamSettings").Get("security").MustString() == "reality"

	realityConfig := new(api.REALITYConfig)
	if enableVless {
		// parse reality config
		realityConfig = &api.REALITYConfig{
			Dest:             inboundInfo.Get("streamSettings").Get("realitySettings").Get("dest").MustString(),
			ProxyProtocolVer: inboundInfo.Get("streamSettings").Get("realitySettings").Get("xver").MustUint64(),
			ServerNames:      inboundInfo.Get("streamSettings").Get("realitySettings").Get("serverNames").MustStringArray(),
			PrivateKey:       inboundInfo.Get("streamSettings").Get("realitySettings").Get("privateKey").MustString(),
			MinClientVer:     inboundInfo.Get("streamSettings").Get("realitySettings").Get("minClientVer").MustString(),
			MaxClientVer:     inboundInfo.Get("streamSettings").Get("realitySettings").Get("maxClientVer").MustString(),
			MaxTimeDiff:      inboundInfo.Get("streamSettings").Get("realitySettings").Get("maxTimeDiff").MustUint64(),
			ShortIds:         inboundInfo.Get("streamSettings").Get("realitySettings").Get("shortIds").MustStringArray(),
		}
	}

	// XTLS only supports TLS and REALITY directly for now
	if (transportProtocol == "grpc" || transportProtocol == "h2") && enableReality {
		vlessFlow = ""
	} else if transportProtocol == "tcp" && enableReality {
		vlessFlow = "xtls-rprx-vision"
	} else {
		vlessFlow = c.VlessFlow
	}

	// Create GeneralNodeInfo
	// AlterID will be updated after next sync
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		AlterID:           0,
		TransportProtocol: transportProtocol,
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
		EnableVless:       enableVless,
		VlessFlow:         vlessFlow,
		ServiceName:       serviceName,
		Header:            header,
		EnableREALITY:     enableReality,
		REALITYConfig:     realityConfig,
	}
	return nodeInfo, nil
}
