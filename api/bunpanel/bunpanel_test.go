package bunpanel_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/bunpanel"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://localhost:8080",
		Key:      "123456",
		NodeID:   1,
		NodeType: "V2ray",
	}
	client := bunpanel.New(apiConfig)
	return client
}

func TestGetV2rayNodeInfo(t *testing.T) {
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Shadowsocks",
	}
	client := bunpanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeInfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Trojan",
	}
	client := bunpanel.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   1111,
			Download: 2222,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}
