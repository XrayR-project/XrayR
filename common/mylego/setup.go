package mylego

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/crypto/acme"
)

const filePerm os.FileMode = 0o600

func setup(accountsStorage *AccountsStorage) (*Account, *lego.Client) {
	keyType := certcrypto.EC256
	privateKey := accountsStorage.GetPrivateKey(keyType)

	var account *Account
	if accountsStorage.ExistsAccountFilePath() {
		account = accountsStorage.LoadAccount(privateKey)
	} else {
		account = &Account{Email: accountsStorage.GetUserID(), key: privateKey}
	}

	client := newClient(account, keyType)

	return account, client
}

func newClient(acc registration.User, keyType certcrypto.KeyType) *lego.Client {
	config := lego.NewConfig(acc)
	config.CADirURL = acme.LetsEncryptURL

	config.Certificate = lego.CertificateConfig{
		KeyType: keyType,
		Timeout: 30 * time.Second,
	}
	config.UserAgent = "lego-cli/dev"

	client, err := lego.NewClient(config)
	if err != nil {
		log.Panicf("Could not create client: %v", err)
	}

	return client
}

func createNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}

func setupChallenges(l *LegoCMD, client *lego.Client) {
	switch l.C.CertMode {
	case "http":
		err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", ""))
		if err != nil {
			log.Panic(err)
		}
	case "tls":
		err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", ""))
		if err != nil {
			log.Panic(err)
		}
	case "dns":
		setupDNS(l.C.Provider, client)
	default:
		log.Panic("No challenge selected. You must specify at least one challenge: `http`, `tls`, `dns`.")
	}
}

func setupDNS(p string, client *lego.Client) {
	provider, err := dns.NewDNSChallengeProviderByName(p)
	if err != nil {
		log.Panic(err)
	}

	err = client.Challenge.SetDNS01Provider(
		provider,
		dns01.CondOption(true, dns01.AddDNSTimeout(10*time.Second)),
	)
	if err != nil {
		log.Panic(err)
	}
}
