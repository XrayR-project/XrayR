package limiter

import (
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

func TestRuntimeKeySupportsLimiterAndAliveSync(t *testing.T) {
	l := New()
	tag := "Socks_127.0.0.1_1080_1"
	users := []api.UserInfo{
		{
			UID:         72,
			Email:       "ignored@example.com",
			RuntimeKey:  "SOCKS-USER",
			DeviceLimit: 1,
		},
	}

	if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter failed: %v", err)
	}

	info, ok := l.GetUserInfo(tag, "SOCKS-USER")
	if !ok {
		t.Fatal("expected runtime key lookup to succeed")
	}
	if info.UID != 72 {
		t.Fatalf("unexpected uid: %d", info.UID)
	}

	if _, _, reject := l.GetUserBucket(tag, "SOCKS-USER", "1.2.3.4"); reject {
		t.Fatal("unexpected reject for first device")
	}
	if _, _, reject := l.GetUserBucket(tag, "SOCKS-USER", "5.6.7.8"); !reject {
		t.Fatal("expected second device to be rejected by device limit")
	}

	online, err := l.GetOnlineDevice(tag)
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}
	if len(*online) != 1 {
		t.Fatalf("unexpected online user count: %d", len(*online))
	}
	if (*online)[0].UID != 72 || (*online)[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected online user: %+v", (*online)[0])
	}

	if err := l.SyncAliveList(tag, map[int][]string{72: []string{"9.9.9.9"}}); err != nil {
		t.Fatalf("SyncAliveList failed: %v", err)
	}

	online, err = l.GetOnlineDevice(tag)
	if err != nil {
		t.Fatalf("GetOnlineDevice after sync failed: %v", err)
	}
	if len(*online) != 1 {
		t.Fatalf("unexpected online user count after sync: %d", len(*online))
	}
	if (*online)[0].UID != 72 || (*online)[0].IP != "9.9.9.9" {
		t.Fatalf("unexpected online user after sync: %+v", (*online)[0])
	}
}
