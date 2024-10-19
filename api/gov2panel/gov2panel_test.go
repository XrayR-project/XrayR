package gov2panel_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/gov2panel"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/util/gconv"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://localhost:8080",
		Key:      "123456",
		NodeID:   90,
		NodeType: "V2ray",
	}
	client := gov2panel.New(apiConfig)
	return client
}

func TestGetNodeInfo(t *testing.T) {
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}

	nodeInfoJson := gjson.New(nodeInfo)
	t.Log(nodeInfoJson.String())
	t.Log(nodeInfoJson.String())
}

func TestGetUserList(t *testing.T) {
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(len(*userList))
	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	t.Log(userList)
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   1073741824,
			Download: 1073741824,
		}
	}

	t.Log(gconv.String(generalUserTraffic))
	client = CreateClient()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
	t.Error(err)
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
