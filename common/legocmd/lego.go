// Let's Encrypt client to go!
// CLI application for generating Let's Encrypt certificates using the ACME package.
package legocmd

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/XrayR-project/XrayR/common/legocmd/cmd"
	"github.com/urfave/cli"
)

var version = "dev"
var defaultPath string

type LegoCMD struct {
	cmdClient *cli.App
}

func New() (*LegoCMD, error) {
	app := cli.NewApp()
	app.Name = "lego"
	app.HelpName = "lego"
	app.Usage = "Let's Encrypt client written in Go"
	app.EnableBashCompletion = true

	app.Version = version
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("lego version %s %s/%s\n", c.App.Version, runtime.GOOS, runtime.GOARCH)
	}

	// Set default path to configPath/cert
	var path string = ""
	configPath := os.Getenv("XRAY_LOCATION_CONFIG")
	if configPath != "" {
		path = configPath
	} else if cwd, err := os.Getwd(); err==nil{
		path = cwd
	} else {
		path = "."
	}
	
	defaultPath = filepath.Join(path, "cert")

	app.Flags = cmd.CreateFlags(defaultPath)

	app.Before = cmd.Before

	app.Commands = cmd.CreateCommands()

	lego := &LegoCMD{
		cmdClient: app,
	}

	return lego, nil
}

// DNSCert cert a domain using DNS API
func (l *LegoCMD) DNSCert(domain, email, provider string, DNSEnv map[string]string) (CertPath string, KeyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknow panic")
			}
			return "", "", err
		}
		return CertPath, KeyPath, nil
	}()
	// Set Env for DNS configuration
	for key, value := range DNSEnv {
		os.Setenv(key, value)
	}
	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertfile(domain)
	if err == nil {
		return CertPath, KeyPath, err
	}

	argstring := fmt.Sprintf("lego -a -d %s -m %s --dns %s run", domain, email, provider)
	err = l.cmdClient.Run(strings.Split(argstring, " "))
	if err != nil {
		return "", "", err
	}
	CertPath, KeyPath, err = checkCertfile(domain)
	if err != nil {
		return "", "", err
	}
	return CertPath, KeyPath, nil
}

// HTTPCert cert a domain using http methods
func (l *LegoCMD) HTTPCert(domain, email string) (CertPath string, KeyPath string, err error) {
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknow panic")
			}
			return "", "", err
		}
		return CertPath, KeyPath, nil
	}()
	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertfile(domain)
	if err == nil {
		return CertPath, KeyPath, err
	}
	argstring := fmt.Sprintf("lego -a -d %s -m %s --http run", domain, email)
	err = l.cmdClient.Run(strings.Split(argstring, " "))

	if err != nil {
		return "", "", err
	}
	CertPath, KeyPath, err = checkCertfile(domain)
	if err != nil {
		return "", "", err
	}
	return CertPath, KeyPath, nil
}

//RenewCert renew a domain cert
func (l *LegoCMD) RenewCert(domain, email, certMode, provider string, DNSEnv map[string]string) (CertPath string, KeyPath string, err error) {
	var argstring string
	defer func() (string, string, error) {
		// Handle any error
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknow panic")
			}
			return "", "", err
		}
		return CertPath, KeyPath, nil
	}()
	if certMode == "http" {
		argstring = fmt.Sprintf("lego -a -d %s -m %s --http renew --days 30", domain, email)
	} else if certMode == "dns" {
		// Set Env for DNS configuration
		for key, value := range DNSEnv {
			os.Setenv(key, value)
		}
		argstring = fmt.Sprintf("lego -a -d %s -m %s --dns %s renew --days 30", domain, email, provider)
	} else {
		return "", "", fmt.Errorf("Unsupport cert mode: %s", certMode)
	}
	err = l.cmdClient.Run(strings.Split(argstring, " "))

	if err != nil {
		return "", "", err
	}
	CertPath, KeyPath, err = checkCertfile(domain)
	if err != nil {
		return "", "", err
	}
	return CertPath, KeyPath, nil
}
func checkCertfile(domain string) (string, string, error) {
	keyPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.key", domain))
	certPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.crt", domain))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("Cert key failed: %s", domain)
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("Cert cert failed: %s", domain)
	}
	absKeyPath, _ := filepath.Abs(keyPath)
	absCertPath, _ := filepath.Abs(certPath)
	return absCertPath, absKeyPath, nil
}
