package controller

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/XrayR-project/XrayR/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server       *core.Instance
	config       *Config
	clientInfo   api.ClientInfo
	apiClient    api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	userList     *[]api.UserInfo
	tasks        []periodicTask
	limitedUsers map[api.UserInfo]LimitInfo
	warnedUsers  map[api.UserInfo]int
	panelType    string
	ibm          inbound.Manager
	obm          outbound.Manager
	stm          stats.Manager
	pm           policy.Manager
	dispatcher   *mydispatcher.DefaultDispatcher
	startAt      time.Time
	logger       *log.Entry
}

type periodicTask struct {
	tag string
	*task.Periodic
}

type remoteCertFileSyncer interface {
	SyncRemoteCertFiles(certConfig *mylego.CertConfig) (bool, error)
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": api.Describe().APIHost,
		"Type": api.Describe().NodeType,
		"ID":   api.Describe().NodeID,
	})
	ibmRaw := server.GetFeature(inbound.ManagerType())
	ibmTyped, ok := ibmRaw.(inbound.Manager)
	if !ok {
		logger.Panicf("failed to get inbound.Manager feature, got %T", ibmRaw)
	}
	obmRaw := server.GetFeature(outbound.ManagerType())
	obmTyped, ok := obmRaw.(outbound.Manager)
	if !ok {
		logger.Panicf("failed to get outbound.Manager feature, got %T", obmRaw)
	}
	stmRaw := server.GetFeature(stats.ManagerType())
	stmTyped, ok := stmRaw.(stats.Manager)
	if !ok {
		logger.Panicf("failed to get stats.Manager feature, got %T", stmRaw)
	}
	pmRaw := server.GetFeature(policy.ManagerType())
	pmTyped, ok := pmRaw.(policy.Manager)
	if !ok {
		logger.Panicf("failed to get policy.Manager feature, got %T", pmRaw)
	}
	dispRaw := server.GetFeature(mydispatcher.Type())
	dispTyped, ok := dispRaw.(*mydispatcher.DefaultDispatcher)
	if !ok {
		logger.Panicf("failed to get mydispatcher.DefaultDispatcher feature, got %T", dispRaw)
	}

	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        ibmTyped,
		obm:        obmTyped,
		stm:        stmTyped,
		pm:         pmTyped,
		dispatcher: dispTyped,
		startAt:    time.Now(),
		logger:     logger,
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 || newNodeInfo.Port > 65535 {
		return fmt.Errorf("invalid server port: %d, must be 1-65535", newNodeInfo.Port)
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	if updated, err := c.syncRemoteCertFiles(); err != nil {
		c.logger.Printf("Startup certificate prefetch failed: %v", err)
	} else if updated {
		c.logger.Infof("Certificate files prefetched for %s before startup", c.config.CertConfig.CertDomain)
	}

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		c.logger.Panic(err)
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.userList = userInfo

	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "user monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Check cert service in need
	if c.nodeInfo.EnableTLS && c.config.EnableREALITY == false {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

func (c *Controller) syncRemoteCertFiles() (bool, error) {
	if c.config == nil || c.config.CertConfig == nil {
		return false, nil
	}
	if c.config.CertConfig.CertMode != "file" {
		return false, nil
	}

	syncer, ok := c.apiClient.(remoteCertFileSyncer)
	if !ok {
		return false, nil
	}

	return syncer.SyncRemoteCertFiles(c.config.CertConfig)
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Panicf("%s periodic task close failed: %s", c.tasks[i].tag, err)
			}
		}
	}

	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			c.logger.Print(err)
			return nil
		}
	}
	if newNodeInfo.Port == 0 || newNodeInfo.Port > 65535 {
		return fmt.Errorf("invalid server port: %d, must be 1-65535", newNodeInfo.Port)
	}

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = c.userList
		} else {
			c.logger.Print(err)
			return nil
		}
	}

	// If nodeInfo changed
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			nodeInfoChanged = true
			// Remove Old limiter
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				c.logger.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
		}
	}

	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				c.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			c.logger.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			c.logger.Print(err)
			return nil
		}

	} else {
		var deleted, added []api.UserInfo
		if usersChanged {
			// Socks/HTTP don't support incremental user changes — full rebuild
			if c.nodeInfo.NodeType == "Socks" || c.nodeInfo.NodeType == "HTTP" {
				if err := c.rebuildInboundWithUsers(newUserInfo, c.nodeInfo); err != nil {
					c.logger.Print(err)
				}
				if err := c.AddInboundLimiter(c.Tag, c.nodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
					c.logger.Print(err)
				}
				deleted, added = compareUserList(c.userList, newUserInfo)
			} else {
				deleted, added = compareUserList(c.userList, newUserInfo)
				if len(deleted) > 0 {
					deletedEmail := make([]string, len(deleted))
					for i, u := range deleted {
						deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
					}
					err := c.removeUsers(deletedEmail, c.Tag)
					if err != nil {
						c.logger.Print(err)
					}
				}
				if len(added) > 0 {
					err = c.addNewUser(&added, c.nodeInfo)
					if err != nil {
						c.logger.Print(err)
					}
					// Update Limiter
					if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
						c.logger.Print(err)
					}
				}
			}
		}
		c.logger.Printf("%d user deleted, %d user added", len(deleted), len(added))
	}
	c.userList = newUserInfo
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	// Socks/HTTP inbounds are built with users embedded (no UserManager support).
	// Skip here — the inbound will be created by rebuildInboundWithUsers() in addNewUser().
	if newNodeInfo.NodeType == "Socks" || newNodeInfo.NodeType == "HTTP" {
		// Still need the outbound for routing
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		return c.addOutbound(outBoundConfig)
	}

	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", c.Tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

// rebuildInboundWithUsers rebuilds the socks/http inbound with all users embedded.
// This is needed because socks/http inbounds don't support proxy.UserManager.
func (c *Controller) rebuildInboundWithUsers(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) error {
	// Remove existing inbound if present (ignore errors for first-time setup)
	_ = c.removeInbound(c.Tag)

	// Build inbound with all users
	inboundConfig, err := InboundBuilderWithUsers(c.config, nodeInfo, c.Tag, userInfo)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {
		return err
	}

	c.logger.Printf("Rebuilt %s inbound with %d users", nodeInfo.NodeType, len(*userInfo))
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	// Socks/HTTP don't support proxy.UserManager — rebuild entire inbound with users embedded
	if nodeInfo.NodeType == "Socks" || nodeInfo.NodeType == "HTTP" {
		return c.rebuildInboundWithUsers(userInfo, nodeInfo)
	}

	users := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless":
		if nodeInfo.EnableVless || (nodeInfo.NodeType == "Vless" && nodeInfo.NodeType != "Vmess") {
			users = c.buildVlessUser(userInfo)
		} else {
			users = c.buildVmessUser(userInfo)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	// Use UID as the primary key for O(N) comparison instead of the full struct
	// which is expensive to hash with 50k users.
	type userKey struct {
		UID   int
		Email string
	}

	oldMap := make(map[userKey]api.UserInfo, len(*old))
	for _, v := range *old {
		oldMap[userKey{v.UID, v.Email}] = v
	}

	newMap := make(map[userKey]struct{}, len(*new))
	for _, v := range *new {
		k := userKey{v.UID, v.Email}
		newMap[k] = struct{}{}
		if _, exists := oldMap[k]; !exists {
			added = append(added, v)
		}
	}

	for k, v := range oldMap {
		if _, exists := newMap[k]; !exists {
			deleted = append(deleted, v)
		}
	}

	return deleted, added
}

func limitUser(c *Controller, user api.UserInfo, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	c.logger.Printf("Limit User: %s Speed: %d End: %s", c.buildUserTag(&user), c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 && len(c.limitedUsers) > 0 {
		toReleaseUsers := make([]api.UserInfo, 0)
		now := time.Now().Unix()
		for user, limitInfo := range c.limitedUsers {
			if now > limitInfo.end {
				user.SpeedLimit = limitInfo.originSpeedLimit
				toReleaseUsers = append(toReleaseUsers, user)
				delete(c.limitedUsers, user)
			}
		}
		if len(toReleaseUsers) > 0 {
			c.logger.Printf("Releasing %d speed-limited users, %d still limited", len(toReleaseUsers), len(c.limitedUsers))
			if err := c.UpdateInboundLimiter(c.Tag, &toReleaseUsers); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Get User traffic — optimized: pre-allocate and batch
	userCount := len(*c.userList)
	userTraffic := make([]api.UserTraffic, 0, userCount/10) // typically ~10% have traffic
	upCounterList := make([]stats.Counter, 0, userCount/10)
	downCounterList := make([]stats.Counter, 0, userCount/10)
	AutoSpeedLimit := int64(c.config.AutoSpeedLimitConfig.Limit)
	UpdatePeriodic := int64(c.config.UpdatePeriodic)
	limitedUsers := make([]api.UserInfo, 0)
	speedThreshold := AutoSpeedLimit * 1000000 * UpdatePeriodic / 8
	for _, user := range *c.userList {
		userTag := c.buildUserTag(&user)
		up, down, upCounter, downCounter := c.getTraffic(userTag)
		if up > 0 || down > 0 {
			// Over speed users
			if AutoSpeedLimit > 0 {
				if down > speedThreshold || up > speedThreshold {
					if _, ok := c.limitedUsers[user]; !ok {
						if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
							limitUser(c, user, &limitedUsers)
						} else {
							c.warnedUsers[user] += 1
							if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
								limitUser(c, user, &limitedUsers)
								delete(c.warnedUsers, user)
							}
						}
					}
				} else {
					delete(c.warnedUsers, user)
				}
			}
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		} else {
			delete(c.warnedUsers, user)
		}
	}
	if len(limitedUsers) > 0 {
		if err := c.UpdateInboundLimiter(c.Tag, &limitedUsers); err != nil {
			c.logger.Print(err)
		}
	}
	if len(userTraffic) > 0 {
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		var err error // Define an empty error
		if !c.config.DisableUploadTraffic {
			err = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		// If report traffic error, not clear the traffic
		if err != nil {
			c.logger.Print(err)
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(c.Tag); err != nil {
		c.logger.Print(err)
	} else if len(*onlineDevice) > 0 {
		if err = c.apiClient.ReportNodeOnlineUsers(onlineDevice); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d online users", len(*onlineDevice))
		}
	}

	// Sync alive list from panel for device limit accuracy
	if aliveList, err := c.apiClient.GetAliveList(); err == nil && aliveList != nil && len(aliveList) > 0 {
		if err := c.dispatcher.Limiter.SyncAliveList(c.Tag, aliveList); err != nil {
			c.logger.Print(err)
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
		}

	}
	return nil
}

func (c *Controller) buildNodeTag() string {
	// Normalize NodeType for tag prefix so same-node routing and data path guards
	// consistently recognize managed protocols.
	base := c.nodeInfo.NodeType
	switch strings.ToLower(base) {
	case "vless":
		base = "VLESS"
	case "trojan":
		base = "Trojan"
	case "vmess", "v2ray":
		base = "Vmess"
	case "shadowsocks":
		base = "Shadowsocks"
	case "socks":
		base = "Socks"
	case "http":
		base = "HTTP"
	}

	// Include NodeID to avoid cross-node mixing when multiple logical nodes share
	// the same NodeType/ListenIP/Port (e.g., CDN or multi-node deployments).
	return fmt.Sprintf("%s_%s_%d_%d", base, c.config.ListenIP, c.nodeInfo.Port, c.nodeInfo.NodeID)
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }

// Check Cert
func (c *Controller) certMonitor() error {
	if c.config == nil || c.config.CertConfig == nil {
		return nil
	}
	if c.nodeInfo.EnableTLS && c.config.EnableREALITY == false {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				c.logger.Print(err)
			}
			// Xray-core supports the OcspStapling certification hot renew
			_, _, _, err = lego.RenewCert()
			if err != nil {
				c.logger.Print(err)
			}
		case "file":
			if updated, err := c.syncRemoteCertFiles(); err != nil {
				c.logger.Print(err)
			} else if updated {
				c.logger.Infof("Certificate files updated for %s; xray-core will hot-reload the new pair automatically", c.config.CertConfig.CertDomain)
			}
		}
	}
	return nil
}
