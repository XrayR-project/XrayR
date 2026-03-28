package v2raysocks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280002,
		NodeType: "V2ray",
	}
	client := New(apiConfig)
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
	client := New(apiConfig)
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
	client := New(apiConfig)
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

func TestSyncRemoteCertFilesSkipsWhenDisabled(t *testing.T) {
	requests := 0
	client := New(&api.Config{
		APIHost:  "https://panel.example/web_api.php",
		Key:      "token-key",
		NodeID:   88,
		NodeType: "V2ray",
	})
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return newHTTPResponse(r, http.StatusOK, nil), nil
	}))

	updated, err := client.SyncRemoteCertFiles(&mylego.CertConfig{
		CertMode: "dns",
	})
	if err != nil {
		t.Fatalf("SyncRemoteCertFiles returned error: %v", err)
	}
	if updated {
		t.Fatal("SyncRemoteCertFiles reported update for disabled config")
	}
	if requests != 0 {
		t.Fatalf("expected no remote requests, got %d", requests)
	}
}

func TestSyncRemoteCertFilesNoChange(t *testing.T) {
	certPEM, keyPEM := mustGeneratePEMPair(t, "same.example.com")
	certPath, keyPath := mustWriteCertPair(t, certPEM, keyPEM)

	client := New(&api.Config{
		APIHost:  "https://panel.example/web_api.php",
		Key:      "token-key",
		NodeID:   88,
		NodeType: "V2ray",
	})
	client.client.SetTransport(newCertRoundTripper(t, certPEM, keyPEM))

	updated, err := client.SyncRemoteCertFiles(&mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "same.example.com",
		CertFile:   certPath,
		KeyFile:    keyPath,
	})
	if err != nil {
		t.Fatalf("SyncRemoteCertFiles returned error: %v", err)
	}
	if updated {
		t.Fatal("expected no update when remote certificate pair matches local files")
	}

	assertFileContent(t, certPath, certPEM)
	assertFileContent(t, keyPath, keyPEM)
}

func TestSyncRemoteCertFilesUpdatesLocalFiles(t *testing.T) {
	localCert, localKey := mustGeneratePEMPair(t, "old.example.com")
	certPath, keyPath := mustWriteCertPair(t, localCert, localKey)

	remoteCert, remoteKey := mustGeneratePEMPair(t, "new.example.com")
	client := New(&api.Config{
		APIHost:  "https://panel.example/web_api.php",
		Key:      "token-key",
		NodeID:   88,
		NodeType: "Vless",
	})
	client.client.SetTransport(newCertRoundTripper(t, remoteCert, remoteKey))

	updated, err := client.SyncRemoteCertFiles(&mylego.CertConfig{
		CertMode:   "file",
		CertDomain: "new.example.com",
		CertFile:   certPath,
		KeyFile:    keyPath,
	})
	if err != nil {
		t.Fatalf("SyncRemoteCertFiles returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected update when remote certificate pair differs from local files")
	}

	assertFileContent(t, certPath, remoteCert)
	assertFileContent(t, keyPath, remoteKey)
}

func TestFetchRemotePanelConfigFilesSkipsDisabledItems(t *testing.T) {
	requests := 0
	client := New(&api.Config{
		APIHost:  "https://panel.example/web_api.php",
		Key:      "token-key",
		NodeID:   88,
		NodeType: "V2ray",
	})
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return newHTTPResponse(r, http.StatusOK, nil), nil
	}))

	files, err := client.FetchRemotePanelConfigFiles(&api.RemotePanelConfigFetchOptions{})
	if err != nil {
		t.Fatalf("FetchRemotePanelConfigFiles returned error: %v", err)
	}
	if files == nil {
		t.Fatal("expected non-nil files payload")
	}
	if requests != 0 {
		t.Fatalf("expected no remote requests, got %d", requests)
	}
}

func TestFetchRemotePanelConfigFiles(t *testing.T) {
	client := New(&api.Config{
		APIHost:  "https://panel.example/web_api.php",
		Key:      "token-key",
		NodeID:   88,
		NodeType: "V2ray",
	})
	client.client.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.URL.Query().Get("node_id"); got != "88" {
			t.Fatalf("unexpected node_id query value: %q", got)
		}
		if got := r.URL.Query().Get("token"); got != "token-key" {
			t.Fatalf("unexpected token query value: %q", got)
		}
		if got := r.URL.Query().Get("node_type"); got != "" {
			t.Fatalf("expected panel config request without node_type, got %q", got)
		}

		switch r.URL.Query().Get("act") {
		case "get_dns_config_json":
			return newHTTPResponse(r, http.StatusOK, []byte(`{"hosts":{"dns.test":"1.1.1.1"}}`)), nil
		case "get_inbound_config_json":
			return newHTTPResponse(r, http.StatusOK, []byte(`[{"tag":"custom-in","protocol":"dokodemo-door","port":12345,"settings":{"address":"127.0.0.1"}}]`)), nil
		default:
			t.Fatalf("unexpected act query value: %q", r.URL.Query().Get("act"))
			return nil, nil
		}
	}))

	files, err := client.FetchRemotePanelConfigFiles(&api.RemotePanelConfigFetchOptions{
		DNS:     true,
		Inbound: true,
	})
	if err != nil {
		t.Fatalf("FetchRemotePanelConfigFiles returned error: %v", err)
	}
	if got := string(files.DNS); got != `{"hosts":{"dns.test":"1.1.1.1"}}` {
		t.Fatalf("unexpected DNS config body: %q", got)
	}
	if got := string(files.Inbound); got != `[{"tag":"custom-in","protocol":"dokodemo-door","port":12345,"settings":{"address":"127.0.0.1"}}]` {
		t.Fatalf("unexpected inbound config body: %q", got)
	}
	if len(files.Route) != 0 || len(files.Outbound) != 0 {
		t.Fatal("expected untouched config items to stay empty")
	}
}

func newCertRoundTripper(t *testing.T, certPEM, keyPEM []byte) http.RoundTripper {
	t.Helper()

	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.URL.Query().Get("node_id"); got != "88" {
			t.Fatalf("unexpected node_id query value: %q", got)
		}
		if got := r.URL.Query().Get("token"); got != "token-key" {
			t.Fatalf("unexpected token query value: %q", got)
		}
		if got := r.URL.Query().Get("node_type"); got != "v2ray" {
			t.Fatalf("unexpected node_type query value: %q", got)
		}

		switch r.URL.Query().Get("act") {
		case "get_certificate":
			return newHTTPResponse(r, http.StatusOK, certPEM), nil
		case "get_key":
			return newHTTPResponse(r, http.StatusOK, keyPEM), nil
		default:
			t.Fatalf("unexpected act query value: %q", r.URL.Query().Get("act"))
			return nil, nil
		}
	})
}

func mustWriteCertPair(t *testing.T, certPEM, keyPEM []byte) (string, string) {
	t.Helper()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write test cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write test key file: %v", err)
	}

	return certPath, keyPath
}

func mustGeneratePEMPair(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected content in %s", path)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newHTTPResponse(req *http.Request, statusCode int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}
