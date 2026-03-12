package newV2board

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

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
	resp          atomic.Value
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
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)

	var nodeType string

	if apiConfig.NodeType == "V2ray" && apiConfig.EnableVless {
		nodeType = "vless"
	} else {
		nodeType = strings.ToLower(apiConfig.NodeType)
	}
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": nodeType,
		"token":     apiConfig.Key,
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
			pattern, err := regexp.Compile(fileScanner.Text())
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
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: "", NodeType: c.NodeType}
}

// GetXrayRCertConfig is not provided by newV2board; return nil to indicate absence.
func (c *APIClient) GetXrayRCertConfig() (*api.XrayRCertConfig, error) {
	return nil, nil
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
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err)
	}

	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), res.String(), err)
	}

	rtn, err := simplejson.NewJson(res.Body())
	if err != nil {
		return nil, fmt.Errorf("ret %s invalid", res.String())
	}

	return rtn, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := "/api/v1/server/UniProxy/config"

	res, err := c.client.R().
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

	nodeInfoResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := nodeInfoResp.Encode()
	json.Unmarshal(b, server)

	if server.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}

	c.resp.Store(server)

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.parseV2rayNodeResponse(server)
	case "Trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(server)
	case "Shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(server)
	case "Hysteria2", "hysteria2", "Hysteria", "hysteria":
		nodeInfo, err = c.parseHysteria2NodeResponse(server)
	case "Tuic", "tuic":
		nodeInfo, err = c.parseTuicNodeResponse(server)
	case "AnyTLS", "anytls":
		nodeInfo, err = c.parseAnyTLSNodeResponse(server)
	case "Socks", "socks":
		nodeInfo, err = c.parseSocksNodeResponse(server)
	case "HTTP", "http":
		nodeInfo, err = c.parseHTTPNodeResponse(server)
	case "Naive", "naive":
		return nil, fmt.Errorf("node type 'naive' (NaïveProxy) is not supported by xray-core backend, please use a dedicated NaïveProxy backend")
	case "Mieru", "mieru":
		return nil, fmt.Errorf("node type 'mieru' is not supported by xray-core backend, please use a dedicated Mieru backend")
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var users []*user
	path := "/api/v1/server/UniProxy/user"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless", "Hysteria2", "hysteria2", "Hysteria", "hysteria", "Tuic", "tuic", "AnyTLS", "anytls", "Socks", "socks", "HTTP", "http":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["users"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("Etag")
	}

	usersResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := usersResp.Get("users").Encode()
	json.Unmarshal(b, &users)
	if len(users) == 0 {
		return nil, errors.New("users is null")
	}

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

		if users[i].DeviceLimit > 0 {
			u.DeviceLimit = users[i].DeviceLimit
		} else {
			u.DeviceLimit = c.DeviceLimit
		}
		u.Email = u.UUID + "@v2board.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}

	return &userList, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/v1/server/UniProxy/push"

	// json structure: {uid1: [u, d], uid2: [u, d], uid1: [u, d], uid3: [u, d]}
	data := make(map[int][]int64, len(*userTraffic))
	for _, traffic := range *userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := c.resp.Load().(*serverConfig).Routes

	ruleList := c.LocalRuleList

	for i := range routes {
		if routes[i].Action == "block" {
			pattern, err := regexp.Compile(strings.Join(routes[i].Match, "|"))
			if err != nil {
				log.Printf("Invalid route rule regex (index=%d): %s, skipping", i, err)
				continue
			}
			ruleList = append(ruleList, api.DetectRule{
				ID:      i,
				Pattern: pattern,
			})
		}
	}

	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := "/api/v1/server/UniProxy/status"

	memUsed := int(math.Round(nodeStatus.Mem))
	diskUsed := int(math.Round(nodeStatus.Disk))
	if memUsed < 0 {
		memUsed = 0
	}
	if diskUsed < 0 {
		diskUsed = 0
	}
	if memUsed > 100 {
		memUsed = 100
	}
	if diskUsed > 100 {
		diskUsed = 100
	}

	payload := map[string]any{
		"cpu": nodeStatus.CPU,
		"mem": map[string]int{
			"total": 100,
			"used":  memUsed,
		},
		"swap": map[string]int{
			"total": 0,
			"used":  0,
		},
		"disk": map[string]int{
			"total": 100,
			"used":  diskUsed,
		},
	}

	res, err := c.client.R().
		SetBody(payload).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	path := "/api/v1/server/UniProxy/alive"

	data := make(map[int][]string)
	for _, user := range *onlineUserList {
		if user.UID == 0 || user.IP == "" {
			continue
		}
		ipNode := fmt.Sprintf("%s_%d", user.IP, c.NodeID)
		data[user.UID] = append(data[user.UID], ipNode)
	}

	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseTrojanNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		host        string
		header      json.RawMessage
		serviceName string
	)

	transportProtocol := "tcp"
	if s.Network != "" {
		transportProtocol = s.Network
	}

	switch s.Network {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp", "":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "grpc":
		serviceName = s.NetworkSettings.ServiceName
	case "httpupgrade":
		if s.NetworkSettings.Headers != nil {
			if httpHeaders, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if s.NetworkSettings.Host != "" {
			host = s.NetworkSettings.Host
		}
	case "xhttp", "splithttp":
		if s.NetworkSettings.Host != "" {
			host = s.NetworkSettings.Host
		}
	}

	if host == "" {
		host = s.Host
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: transportProtocol,
		EnableTLS:         true,
		Host:              host,
		ServiceName:       serviceName,
		Path:              s.NetworkSettings.Path,
		Header:            header,
		NameServerConfig:  s.parseDNSConfig(),
	}

	// XHTTP bypass CDN fields for Trojan (same as V2ray/VLESS)
	if transportProtocol == "xhttp" || transportProtocol == "splithttp" {
		nodeInfo.XHTTPMode = s.NetworkSettings.Mode
		nodeInfo.XHTTPExtra = s.NetworkSettings.Extra
		nodeInfo.XPaddingBytes = s.NetworkSettings.XPaddingBytes
		nodeInfo.XPaddingObfsMode = s.NetworkSettings.XPaddingObfsMode
		nodeInfo.XPaddingKey = s.NetworkSettings.XPaddingKey
		nodeInfo.XPaddingHeader = s.NetworkSettings.XPaddingHeader
		nodeInfo.XPaddingPlacement = s.NetworkSettings.XPaddingPlacement
		nodeInfo.XPaddingMethod = s.NetworkSettings.XPaddingMethod
		nodeInfo.UplinkHTTPMethod = s.NetworkSettings.UplinkHTTPMethod
		nodeInfo.SessionPlacement = s.NetworkSettings.SessionPlacement
		nodeInfo.SessionKey = s.NetworkSettings.SessionKey
		nodeInfo.SeqPlacement = s.NetworkSettings.SeqPlacement
		nodeInfo.SeqKey = s.NetworkSettings.SeqKey
		nodeInfo.UplinkDataPlacement = s.NetworkSettings.UplinkDataPlacement
		nodeInfo.UplinkDataKey = s.NetworkSettings.UplinkDataKey
		nodeInfo.UplinkChunkSize = s.NetworkSettings.UplinkChunkSize
		nodeInfo.NoGRPCHeader = s.NetworkSettings.NoGRPCHeader
		nodeInfo.NoSSEHeader = s.NetworkSettings.NoSSEHeader
	}

	return nodeInfo, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseSSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var header json.RawMessage
	var (
		nodeType          = c.NodeType
		transportProtocol = "tcp"
		enableTLS         bool
		path              string
		host              string
		serviceName       string
		port              = uint32(s.ServerPort)
	)

	plugin := strings.ToLower(strings.TrimSpace(s.Plugin))
	if plugin != "" && plugin != "none" {
		switch plugin {
		case "v2ray-plugin", "xray-plugin":
			nodeType = "Shadowsocks-Plugin"
			transportProtocol, enableTLS, host, path, serviceName = parseSSPluginOpts(plugin, s.PluginOpts)
			if port <= 1 {
				return nil, fmt.Errorf("Shadowsocks-Plugin listen port must bigger than 1")
			}
			port--
		case "obfs-local", "simple-obfs":
			mode, obfsHost, obfsPath := parseSimpleObfsOpts(s.PluginOpts)
			if mode == "" || mode == "http" {
				path = obfsPath
				if path == "" {
					path = "/"
				}
				h := simplejson.New()
				h.Set("type", "http")
				h.SetPath([]string{"request", "path"}, path)
				header, _ = h.Encode()
				host = obfsHost
			} else if mode == "tls" {
				return nil, fmt.Errorf("simple-obfs tls mode is not supported")
			} else {
				return nil, fmt.Errorf("unsupported simple-obfs mode: %s", mode)
			}
		default:
			return nil, fmt.Errorf("unsupported shadowsocks plugin: %s", plugin)
		}
	}

	if s.Obfs == "http" {
		path = "/"
		if p := s.ObfsSettings.Path; p != "" {
			if strings.HasPrefix(p, "/") {
				path = p
			} else {
				path += p
			}
		}
		h := simplejson.New()
		h.Set("type", "http")
		h.SetPath([]string{"request", "path"}, path)
		header, _ = h.Encode()
		if host == "" {
			host = s.ObfsSettings.Host
		}
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          nodeType,
		NodeID:            c.NodeID,
		Port:              port,
		TransportProtocol: transportProtocol,
		CypherMethod:      s.Cipher,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		EnableTLS:         enableTLS,
		Path:              path,
		Host:              host,
		ServiceName:       serviceName,
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
	}, nil
}

// parseV2rayNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseV2rayNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		host          string
		header        json.RawMessage
		enableTLS     bool
		enableREALITY bool
		dest          string
		xVer          uint64
	)

	if s.VlessTlsSettings.Dest != "" {
		dest = s.VlessTlsSettings.Dest
	} else {
		dest = s.VlessTlsSettings.Sni
	}
	if s.VlessTlsSettings.XVer != 0 {
		xVer = s.VlessTlsSettings.XVer
	} else {
		xVer = 0
	}

	realityConfig := api.REALITYConfig{
		Dest:             dest + ":" + s.VlessTlsSettings.ServerPort,
		ProxyProtocolVer: xVer,
		ServerNames:      []string{s.VlessTlsSettings.Sni},
		PrivateKey:       s.VlessTlsSettings.PrivateKey,
		ShortIds:         []string{s.VlessTlsSettings.ShortId},
	}

	// For backward compatibility with old V2board which used network_settings (snake_case)
	// for VLESS, copy VlessNetworkSettings fields into NetworkSettings only if populated.
	// Xboard and newer panels always use networkSettings (camelCase) for all protocols.
	if c.EnableVless {
		if s.VlessNetworkSettings.Path != "" || s.VlessNetworkSettings.Host != "" ||
			s.VlessNetworkSettings.ServiceName != "" || s.VlessNetworkSettings.Headers != nil ||
			s.VlessNetworkSettings.Header != nil {
			s.NetworkSettings.Path = s.VlessNetworkSettings.Path
			s.NetworkSettings.Host = s.VlessNetworkSettings.Host
			s.NetworkSettings.Headers = s.VlessNetworkSettings.Headers
			s.NetworkSettings.ServiceName = s.VlessNetworkSettings.ServiceName
			s.NetworkSettings.Header = s.VlessNetworkSettings.Header
		}
	}

	switch s.Network {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "httpupgrade", "splithttp":
		if s.NetworkSettings.Headers != nil {
			if httpHeaders, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if s.NetworkSettings.Host != "" {
			host = s.NetworkSettings.Host
		}
	}

	switch s.Tls {
	case 0:
		enableTLS = false
		enableREALITY = false
	case 1:
		enableTLS = true
		enableREALITY = false
	case 2:
		enableTLS = true
		enableREALITY = true
	}

	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		AlterID:           0,
		TransportProtocol: s.Network,
		EnableTLS:         enableTLS,
		Path:              s.NetworkSettings.Path,
		Host:              host,
		EnableVless:       c.EnableVless,
		VlessFlow:         s.VlessFlow,
		ServiceName:       s.NetworkSettings.ServiceName,
		Header:            header,
		EnableREALITY:     enableREALITY,
		REALITYConfig:     &realityConfig,
		NameServerConfig:  s.parseDNSConfig(),
		// XHTTP bypass CDN fields
		XHTTPMode:           s.NetworkSettings.Mode,
		XHTTPExtra:          s.NetworkSettings.Extra,
		XPaddingBytes:       s.NetworkSettings.XPaddingBytes,
		XPaddingObfsMode:    s.NetworkSettings.XPaddingObfsMode,
		XPaddingKey:         s.NetworkSettings.XPaddingKey,
		XPaddingHeader:      s.NetworkSettings.XPaddingHeader,
		XPaddingPlacement:   s.NetworkSettings.XPaddingPlacement,
		XPaddingMethod:      s.NetworkSettings.XPaddingMethod,
		UplinkHTTPMethod:    s.NetworkSettings.UplinkHTTPMethod,
		SessionPlacement:    s.NetworkSettings.SessionPlacement,
		SessionKey:          s.NetworkSettings.SessionKey,
		SeqPlacement:        s.NetworkSettings.SeqPlacement,
		SeqKey:              s.NetworkSettings.SeqKey,
		UplinkDataPlacement: s.NetworkSettings.UplinkDataPlacement,
		UplinkDataKey:       s.NetworkSettings.UplinkDataKey,
		UplinkChunkSize:     s.NetworkSettings.UplinkChunkSize,
		NoGRPCHeader:        s.NetworkSettings.NoGRPCHeader,
		NoSSEHeader:         s.NetworkSettings.NoSSEHeader,
	}, nil
}

// parseHysteria2NodeResponse parse the response for Hysteria2 nodes.
func (c *APIClient) parseHysteria2NodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if s == nil {
		return nil, errors.New("server config is nil")
	}
	if s.Version != 0 && s.Version != 2 {
		return nil, fmt.Errorf("unsupported hysteria version: %d, only v2 is supported", s.Version)
	}

	hy := &api.Hysteria2Config{
		Obfs:                  s.Obfs,
		ObfsPassword:          s.ObfsPassword,
		UpMbps:                s.UpMbps,
		DownMbps:              s.DownMbps,
		IgnoreClientBandwidth: s.IgnoreClientBandwidth,
		PortHopEnabled:        s.PortHopEnabled,
		PortHopPorts:          s.PortHopPorts,
	}
	if hy.Obfs == "" {
		hy.Obfs = "none"
	}

	sni := s.ServerName
	if sni == "" {
		sni = s.Host
	}

	return &api.NodeInfo{
		NodeType:         "Hysteria2",
		NodeID:           c.NodeID,
		Port:             uint32(s.ServerPort),
		Host:             s.Host,
		SNI:              sni,
		EnableTLS:        true,
		Hysteria2Config:  hy,
		NameServerConfig: s.parseDNSConfig(),
	}, nil
}

// parseTuicNodeResponse parse the response for TUIC nodes.
func (c *APIClient) parseTuicNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if s == nil {
		return nil, errors.New("server config is nil")
	}

	sni := s.ServerName
	if sni == "" {
		sni = s.Host
	}

	return &api.NodeInfo{
		NodeType:  "Tuic",
		NodeID:    c.NodeID,
		Port:      uint32(s.ServerPort),
		Host:      s.Host,
		SNI:       sni,
		EnableTLS: true,
		TuicConfig: &api.TuicConfig{
			CongestionControl: s.CongestionControl,
			ZeroRTTHandshake:  s.ZeroRTTHandshake,
			Heartbeat:         parseHeartbeatSeconds(s.Heartbeat),
			AuthTimeout:       parseHeartbeatSeconds(s.AuthTimeout),
		},
		NameServerConfig: s.parseDNSConfig(),
	}, nil
}

// parseAnyTLSNodeResponse parse the response for AnyTLS nodes.
func (c *APIClient) parseAnyTLSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if s == nil {
		return nil, errors.New("server config is nil")
	}

	sni := s.ServerName
	if sni == "" {
		sni = s.Host
	}

	return &api.NodeInfo{
		NodeType:         "AnyTLS",
		NodeID:           c.NodeID,
		Port:             uint32(s.ServerPort),
		Host:             s.Host,
		SNI:              sni,
		EnableTLS:        true,
		AnyTLSConfig:     &api.AnyTLSConfig{PaddingScheme: s.PaddingScheme},
		NameServerConfig: s.parseDNSConfig(),
	}, nil
}

// parseSocksNodeResponse parse the response for Socks proxy nodes.
func (c *APIClient) parseSocksNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if s == nil {
		return nil, errors.New("server config is nil")
	}

	return &api.NodeInfo{
		NodeType:          "Socks",
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

// parseHTTPNodeResponse parse the response for HTTP proxy nodes.
func (c *APIClient) parseHTTPNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if s == nil {
		return nil, errors.New("server config is nil")
	}

	enableTLS := s.Tls == 1

	return &api.NodeInfo{
		NodeType:          "HTTP",
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		EnableTLS:         enableTLS,
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

func parseHeartbeatSeconds(value string) int {
	if value == "" {
		return 0
	}
	if d, err := time.ParseDuration(value); err == nil {
		return int(d.Seconds())
	}
	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return 0
}

func parseSSPluginOpts(plugin, opts string) (transport string, enableTLS bool, host, path, serviceName string) {
	transport = "tcp"
	if plugin == "v2ray-plugin" || plugin == "xray-plugin" {
		transport = "ws"
	}

	for _, raw := range strings.Split(opts, ";") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		key, val, found := strings.Cut(item, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if !found {
			if key == "tls" {
				enableTLS = true
			}
			continue
		}
		switch key {
		case "mode":
			mode := strings.ToLower(val)
			switch mode {
			case "websocket", "ws":
				transport = "ws"
			case "grpc":
				transport = "grpc"
			}
		case "tls":
			if val == "1" || strings.EqualFold(val, "true") {
				enableTLS = true
			}
		case "host":
			host = val
		case "path":
			path = val
		case "servicename", "service":
			serviceName = val
		}
	}

	return transport, enableTLS, host, path, serviceName
}

func parseSimpleObfsOpts(opts string) (mode, host, path string) {
	for _, raw := range strings.Split(opts, ";") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		key, val, found := strings.Cut(item, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if !found {
			continue
		}
		switch key {
		case "obfs", "mode":
			mode = strings.ToLower(val)
		case "obfs-host", "host":
			host = val
		case "obfs-uri", "uri", "path":
			path = val
		}
	}

	return mode, host, path
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.Routes {
		if s.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(s.Routes[i].ActionValue)},
				Domains: s.Routes[i].Match,
			})
		}
	}

	return
}
