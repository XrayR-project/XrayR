package v2raysocks_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/v2raysocks"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280002,
		NodeType: "V2ray",
	}
	client := v2raysocks.New(apiConfig)
	return client
}

func TestGetV2rayNodeinfo(t *testing.T) {
	client := CreateClient()
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeinfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280009,
		NodeType: "Shadowsocks",
	}
	client := v2raysocks.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeinfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280008,
		NodeType: "Trojan",
	}
	client := v2raysocks.New(apiConfig)
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
			Upload:   114514,
			Download: 114514,
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
