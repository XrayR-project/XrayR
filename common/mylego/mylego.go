package mylego

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var defaultPath string

func New(certConf *CertConfig) (*LegoCMD, error) {
	// Set default path to configPath/cert
	var p = ""
	configPath := os.Getenv("XRAY_LOCATION_CONFIG")
	if configPath != "" {
		p = configPath
	} else if cwd, err := os.Getwd(); err == nil {
		p = cwd
	} else {
		p = "."
	}

	defaultPath = filepath.Join(p, "cert")
	lego := &LegoCMD{
		C:    certConf,
		path: defaultPath,
	}

	return lego, nil
}

func (l *LegoCMD) getPath() string {
	return l.path
}

func (l *LegoCMD) getCertConfig() *CertConfig {
	return l.C
}

// DNSCert cert a domain using DNS API
func (l *LegoCMD) DNSCert() (CertPath string, KeyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", err
		}
		return CertPath, KeyPath, nil
	}()

	// Set Env for DNS configuration
	for key, value := range l.C.DNSEnv {
		os.Setenv(strings.ToUpper(key), value)
	}

	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return CertPath, KeyPath, err
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}
	return CertPath, KeyPath, nil
}

// HTTPCert cert a domain using http methods
func (l *LegoCMD) HTTPCert() (CertPath string, KeyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", err
		}
		return CertPath, KeyPath, nil
	}()

	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return CertPath, KeyPath, err
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}

	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}

	return CertPath, KeyPath, nil
}

// RenewCert renew a domain cert
func (l *LegoCMD) RenewCert() (CertPath string, KeyPath string, ok bool, err error) {
	defer func() (string, string, bool, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			return "", "", false, err
		}
		return CertPath, KeyPath, ok, nil
	}()

	ok, err = l.Renew()
	if err != nil {
		return
	}

	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return
	}

	return
}

func checkCertFile(domain string) (string, string, error) {
	keyPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.key", sanitizedDomain(domain)))
	certPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.crt", sanitizedDomain(domain)))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert key failed: %s", domain)
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert cert failed: %s", domain)
	}
	absKeyPath, _ := filepath.Abs(keyPath)
	absCertPath, _ := filepath.Abs(certPath)
	return absCertPath, absKeyPath, nil
}
