package legocmd_test

import (
	"testing"

	"github.com/XrayR-project/XrayR/common/legocmd"
)

func TestLegoClient(t *testing.T) {
	_, err := legocmd.New()
	if err != nil {
		t.Error(err)
	}
}

func TestLegoDNSCert(t *testing.T) {
	lego, err := legocmd.New()
	if err != nil {
		t.Error(err)
	}
	var (
		domain   string = "node1.test.com"
		email    string = "test@gmail.com"
		provider string = "alidns"
		DNSEnv   map[string]string
	)
	DNSEnv = make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certPath, keyPath, err := lego.DNSCert(domain, email, provider, DNSEnv)
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
}

func TestLegoHTTPCert(t *testing.T) {
	lego, err := legocmd.New()
	if err != nil {
		t.Error(err)
	}
	var (
		domain string = "node1.test.com"
		email  string = "test@gmail.com"
	)
	certPath, keyPath, err := lego.HTTPCert(domain, email)
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
}

func TestLegoRenewCert(t *testing.T) {
	lego, err := legocmd.New()
	if err != nil {
		t.Error(err)
	}
	var (
		domain   string = "node1.test.com"
		email    string = "test@gmail.com"
		provider string = "alidns"
		DNSEnv   map[string]string
	)
	DNSEnv = make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certPath, keyPath, err := lego.RenewCert(domain, email, "dns", provider, DNSEnv)
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)

	certPath, keyPath, err = lego.RenewCert(domain, email, "http", provider, DNSEnv)
	if err != nil {
		t.Error(err)
	}
	t.Log(certPath)
	t.Log(keyPath)
}
