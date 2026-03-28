package v2raysocks

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/XrayR-project/XrayR/common"
	"github.com/XrayR-project/XrayR/common/mylego"
)

const remoteCertFilePerm os.FileMode = 0o600

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
	client.SetHeader("User-Agent", "XrayR/0.9.8")
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
		defer file.Close()

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			pattern, err := common.SafeCompileRegex(fileScanner.Text())
			if err != nil {
				log.Printf("Invalid rule regex: %s, skipping", err)
				continue
			}
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: pattern,
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Printf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: "", NodeType: c.NodeType}
}

// GetXrayRCertConfig is not provided by V2RaySocks panel; return nil to indicate absence.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return nil, nil
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

// SyncRemoteCertFiles fetches certificate and private key PEM content from the
// V2RaySocks panel and replaces the local file-mode certificate pair when the
// remote content changes.
func (c *APIClient) SyncRemoteCertFiles(certConfig *mylego.CertConfig) (bool, error) {
	if !shouldSyncRemoteCertFiles(certConfig) {
		return false, nil
	}

	nodeType, err := normalizeNodeTypeForRemoteCert(c.NodeType)
	if err != nil {
		return false, err
	}

	certBody, err := c.fetchRemoteCertBody("get_certificate", nodeType)
	if err != nil {
		return false, err
	}
	keyBody, err := c.fetchRemoteCertBody("get_key", nodeType)
	if err != nil {
		return false, err
	}
	if len(bytes.TrimSpace(certBody)) == 0 || len(bytes.TrimSpace(keyBody)) == 0 {
		return false, nil
	}

	if _, err := tls.X509KeyPair(certBody, keyBody); err != nil {
		return false, fmt.Errorf("invalid remote certificate or key pair for %s: %w", certConfig.CertDomain, err)
	}

	localCert, err := readExistingFile(certConfig.CertFile)
	if err != nil {
		return false, fmt.Errorf("read local certificate %s: %w", certConfig.CertFile, err)
	}
	localKey, err := readExistingFile(certConfig.KeyFile)
	if err != nil {
		return false, fmt.Errorf("read local key %s: %w", certConfig.KeyFile, err)
	}

	if bytes.Equal(certBody, localCert) && bytes.Equal(keyBody, localKey) {
		return false, nil
	}

	if err := atomicWriteFile(certConfig.CertFile, certBody); err != nil {
		return false, fmt.Errorf("write certificate file %s: %w", certConfig.CertFile, err)
	}
	if err := atomicWriteFile(certConfig.KeyFile, keyBody); err != nil {
		return false, fmt.Errorf("write key file %s: %w", certConfig.KeyFile, err)
	}

	return true, nil
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("request %s failed: status %d", c.assembleURL(path), res.StatusCode())
	}
	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("request %s returned invalid JSON", c.assembleURL(path))
	}
	return rtn, nil
}

func shouldSyncRemoteCertFiles(certConfig *mylego.CertConfig) bool {
	if certConfig == nil {
		return false
	}
	if certConfig.CertMode != "file" {
		return false
	}
	return certConfig.CertDomain != "" && certConfig.CertFile != "" && certConfig.KeyFile != ""
}

func normalizeNodeTypeForRemoteCert(nodeType string) (string, error) {
	switch strings.ToLower(nodeType) {
	case "v2ray", "vmess", "vless":
		return "v2ray", nil
	case "trojan", "shadowsocks", "socks", "http":
		return strings.ToLower(nodeType), nil
	default:
		return "", fmt.Errorf("unsupported Node type: %s", nodeType)
	}
}

func (c *APIClient) fetchRemoteCertBody(act, nodeType string) ([]byte, error) {
	res, err := c.client.R().
		SetQueryParams(map[string]string{
			"act":       act,
			"node_type": nodeType,
		}).
		Get(c.APIHost)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %w", act, err)
	}
	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("request %s failed: status %d", act, res.StatusCode())
	}
	return res.Body(), nil
}

func (c *APIClient) fetchRemotePanelConfigBody(act string) ([]byte, error) {
	res, err := c.client.R().
		SetQueryParam("act", act).
		Get(c.APIHost)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %w", act, err)
	}
	if res.StatusCode() >= 400 {
		return nil, fmt.Errorf("request %s failed: status %d", act, res.StatusCode())
	}
	return res.Body(), nil
}

// FetchRemotePanelConfigFiles fetches optional panel-level JSON snippets used by
// XrayR's global DNS/routing/custom inbound/custom outbound config files.
func (c *APIClient) FetchRemotePanelConfigFiles(opts *api.RemotePanelConfigFetchOptions) (*api.RemotePanelConfigFiles, error) {
	if opts == nil || !opts.Any() {
		return &api.RemotePanelConfigFiles{}, nil
	}

	files := &api.RemotePanelConfigFiles{}
	if opts.DNS {
		body, err := c.fetchRemotePanelConfigBody("get_dns_config_json")
		if err != nil {
			return nil, err
		}
		files.DNS = body
	}
	if opts.Route {
		body, err := c.fetchRemotePanelConfigBody("get_route_config_json")
		if err != nil {
			return nil, err
		}
		files.Route = body
	}
	if opts.Inbound {
		body, err := c.fetchRemotePanelConfigBody("get_inbound_config_json")
		if err != nil {
			return nil, err
		}
		files.Inbound = body
	}
	if opts.Outbound {
		body, err := c.fetchRemotePanelConfigBody("get_outbound_config_json")
		if err != nil {
			return nil, err
		}
		files.Outbound = body
	}
	return files, nil
}

func readExistingFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

func atomicWriteFile(path string, data []byte) error {
	perm, err := filePermForPath(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

func filePermForPath(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return remoteCertFilePerm, nil
		}
		return 0, err
	}
	return info.Mode().Perm(), nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	var nodeType string
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		nodeType = "v2ray"
	case "trojan", "shadowsocks", "socks", "http":
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

	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless":
		nodeInfo, err = c.ParseV2rayNodeResponse(response)
	case "trojan":
		nodeInfo, err = c.ParseTrojanNodeResponse(response)
	case "shadowsocks":
		nodeInfo, err = c.ParseSSNodeResponse(response)
	case "socks":
		nodeInfo, err = c.ParseSocksNodeResponse(response)
	case "http":
		nodeInfo, err = c.ParseHTTPNodeResponse(response)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %v", err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var nodeType string
	switch strings.ToLower(c.NodeType) {
	case "v2ray", "vmess", "vless", "trojan", "shadowsocks", "socks", "http":
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
		switch strings.ToLower(c.NodeType) {
		case "shadowsocks":
			user.Email = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Passwd = response.Get("data").GetIndex(i).Get("secret").MustString()
			user.Method = response.Get("data").GetIndex(i).Get("cipher").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "trojan":
			user.UUID = response.Get("data").GetIndex(i).Get("password").MustString()
			user.Email = response.Get("data").GetIndex(i).Get("password").MustString()
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "v2ray", "vmess", "vless":
			user.UUID = response.Get("data").GetIndex(i).Get("uuid").MustString()
			user.Email = user.UUID + "@x.com"
			user.SpeedLimit = response.Get("data").GetIndex(i).Get("st").MustUint64() * 1000000 / 8
			user.DeviceLimit = response.Get("data").GetIndex(i).Get("dt").MustInt()
		case "socks", "http":
			credential := response.Get("data").GetIndex(i).Get("password").MustString()
			user.UUID = credential
			user.Email = credential
			user.Passwd = credential
			user.RuntimeKey = credential
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

// GetAliveList implements the API interface (not supported by V2RaySocks)
func (c *APIClient) GetAliveList() (map[int][]string, error) {
	return nil, nil
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
	if c.ConfigResp == nil {
		return &ruleList, nil
	}
	ruleListResponse := c.ConfigResp.Get("routing").Get("rules").GetIndex(1).Get("domain").MustStringArray()
	for i, rule := range ruleListResponse {
		rule = strings.TrimPrefix(rule, "regexp:")
		pattern, err := common.SafeCompileRegex(rule)
		if err != nil {
			log.Printf("Invalid rule regex (index=%d): %s, skipping", i, err)
			continue
		}
		ruleListItem := api.DetectRule{
			ID:      i,
			Pattern: pattern,
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

func inboundInfoByProtocol(nodeInfoResponse *simplejson.Json, protocol string) (*simplejson.Json, error) {
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}

	for _, inbound := range tmpInboundInfo {
		inboundMap, ok := inbound.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid inbound info format")
		}
		marshalByte, err := json.Marshal(inboundMap)
		if err != nil {
			return nil, fmt.Errorf("marshal inbound info: %w", err)
		}
		inboundInfo, err := simplejson.NewJson(marshalByte)
		if err != nil {
			return nil, fmt.Errorf("parse inbound info: %w", err)
		}
		if strings.EqualFold(inboundInfo.Get("protocol").MustString(), protocol) {
			return inboundInfo, nil
		}
	}

	return nil, fmt.Errorf("no %s inbound info in response", protocol)
}

// ParseSocksNodeResponse parses the Socks node format returned by V2RaySocks.
func (c *APIClient) ParseSocksNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	port := uint32(nodeInfoResponse.Get("server_port").MustUint64())
	if inboundInfo, err := inboundInfoByProtocol(nodeInfoResponse, "socks"); err == nil {
		port = uint32(inboundInfo.Get("port").MustUint64())
	} else if port == 0 {
		return nil, err
	}

	return &api.NodeInfo{
		NodeType:          "Socks",
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
	}, nil
}

// ParseHTTPNodeResponse parses the HTTP node format returned by V2RaySocks.
func (c *APIClient) ParseHTTPNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	port := uint32(nodeInfoResponse.Get("server_port").MustUint64())
	if inboundInfo, err := inboundInfoByProtocol(nodeInfoResponse, "http"); err == nil {
		port = uint32(inboundInfo.Get("port").MustUint64())
	} else if port == 0 {
		return nil, err
	}

	return &api.NodeInfo{
		NodeType:          "HTTP",
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: "tcp",
	}, nil
}

// ParseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) ParseTrojanNodeResponse(nodeInfoResponse *simplejson.Json) (*api.NodeInfo, error) {
	tmpInboundInfo := nodeInfoResponse.Get("inbounds").MustArray()
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

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
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

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
	if len(tmpInboundInfo) == 0 {
		return nil, fmt.Errorf("no inbound info in response")
	}
	inboundMap, ok := tmpInboundInfo[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid inbound info format")
	}
	marshalByte, err := json.Marshal(inboundMap)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound info: %w", err)
	}
	inboundInfo, err := simplejson.NewJson(marshalByte)
	if err != nil {
		return nil, fmt.Errorf("parse inbound info: %w", err)
	}

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
	case "xhttp":
		host = inboundInfo.Get("streamSettings").Get("xhttpSettings").Get("Host").MustString()
		if host == "" {
			host = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("Host").MustString()
		}
		path = inboundInfo.Get("streamSettings").Get("xhttpSettings").Get("path").MustString()
		if path == "" {
			path = inboundInfo.Get("streamSettings").Get("splithttpSettings").Get("path").MustString()
		}
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
		reality := inboundInfo.Get("streamSettings").Get("realitySettings")
		dest := reality.Get("dest").MustString()
		if dest == "" {
			dest = reality.Get("target").MustString()
		}

		// parse reality config
		realityConfig = &api.REALITYConfig{
			Dest:             dest,
			ProxyProtocolVer: reality.Get("xver").MustUint64(),
			ServerNames:      reality.Get("serverNames").MustStringArray(),
			PrivateKey:       reality.Get("privateKey").MustString(),
			MinClientVer:     reality.Get("minClientVer").MustString(),
			MaxClientVer:     reality.Get("maxClientVer").MustString(),
			MaxTimeDiff:      reality.Get("maxTimeDiff").MustUint64(),
			ShortIds:         reality.Get("shortIds").MustStringArray(),
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

	// Parse XHTTP settings if transport is splithttp/xhttp
	if transportProtocol == "splithttp" || transportProtocol == "xhttp" {
		settingsKey := "splithttpSettings"
		if transportProtocol == "xhttp" {
			if _, ok := inboundInfo.Get("streamSettings").CheckGet("xhttpSettings"); ok {
				settingsKey = "xhttpSettings"
			}
		}
		ss := inboundInfo.Get("streamSettings").Get(settingsKey)
		nodeInfo.XHTTPMode = ss.Get("mode").MustString()
		nodeInfo.XPaddingObfsMode = ss.Get("xPaddingObfsMode").MustBool()
		nodeInfo.XPaddingKey = ss.Get("xPaddingKey").MustString()
		nodeInfo.XPaddingHeader = ss.Get("xPaddingHeader").MustString()
		nodeInfo.XPaddingPlacement = ss.Get("xPaddingPlacement").MustString()
		nodeInfo.XPaddingMethod = ss.Get("xPaddingMethod").MustString()
		nodeInfo.UplinkHTTPMethod = ss.Get("uplinkHTTPMethod").MustString()
		nodeInfo.SessionPlacement = ss.Get("sessionPlacement").MustString()
		nodeInfo.SessionKey = ss.Get("sessionKey").MustString()
		nodeInfo.SeqPlacement = ss.Get("seqPlacement").MustString()
		nodeInfo.SeqKey = ss.Get("seqKey").MustString()
		nodeInfo.UplinkDataPlacement = ss.Get("uplinkDataPlacement").MustString()
		nodeInfo.UplinkDataKey = ss.Get("uplinkDataKey").MustString()
		nodeInfo.UplinkChunkSize = uint32(ss.Get("uplinkChunkSize").MustUint64())
		nodeInfo.NoGRPCHeader = ss.Get("noGRPCHeader").MustBool()
		nodeInfo.NoSSEHeader = ss.Get("noSSEHeader").MustBool()
		if extra := ss.Get("extra"); extra.Interface() != nil {
			if extraBytes, err := extra.MarshalJSON(); err == nil {
				nodeInfo.XHTTPExtra = extraBytes
			}
		}
	}

	return nodeInfo, nil
}
