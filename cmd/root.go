package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/XrayR-project/XrayR/panel"
)

var (
	cfgFile string
	cfgKey  string

	rootCmd = &cobra.Command{
		Use: "XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
	rootCmd.PersistentFlags().StringVarP(&cfgKey, "key", "k", "", "Key to decrypt encrypted config file.")
}

// EVP_BytesToKey 实现 OpenSSL 默认 key/iv 生成算法
func evpBytesToKey(password, salt []byte) (key, iv []byte) {
	var m []byte
	prev := []byte{}
	for len(m) < 48 { // AES-256 key=32 bytes + IV=16 bytes
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		m = append(m, prev...)
	}
	key = m[:32]
	iv = m[32:48]
	return
}

// decryptOpenSSLAES 解密 OpenSSL aes-256-cfb 加密文件
func decryptOpenSSLAES(ciphertext []byte, password string) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var key, iv []byte
	if bytes.HasPrefix(ciphertext, []byte("Salted__")) {
		salt := ciphertext[8:16]
		ciphertext = ciphertext[16:]
		key, iv = evpBytesToKey([]byte(password), salt)
	} else {
		// 没有 salt 的情况，用 MD5 简单生成 key
		sum := md5.Sum([]byte(password))
		key = sum[:]
		if len(ciphertext) < 16 {
			return nil, fmt.Errorf("ciphertext too short for IV")
		}
		iv = ciphertext[:16]
		ciphertext = ciphertext[16:]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")
	}

	if strings.HasSuffix(cfgFile, ".enc") {
		log.Info("Encrypted config detected, decrypting...")
		data, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			log.Panicf("Failed to read config file: %s", err)
		}
		if cfgKey == "" {
			log.Panic("You must provide --key to decrypt encrypted config file")
		}

		plaintext, err := decryptOpenSSLAES(data, cfgKey)
		if err != nil {
			log.Panicf("Decrypt config file failed: %s", err)
		}

		if err := config.ReadConfig(strings.NewReader(string(plaintext))); err != nil {
			log.Panicf("Read decrypted config failed: %s", err)
		}
	} else {
		if err := config.ReadInConfig(); err != nil {
			log.Panicf("Config file error: %s", err)
		}
	}

	config.WatchConfig() // Watch the config
	return config
}

func run() error {
	showVersion()

	config := getConfig()
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	if panelConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	}

	p := panel.New(panelConfig)
	lastTime := time.Now()
	config.OnConfigChange(func(e fsnotify.Event) {
		if time.Now().After(lastTime.Add(3 * time.Second)) {
			fmt.Println("Config file changed:", e.Name)
			p.Close()
			runtime.GC()
			if err := config.Unmarshal(panelConfig); err != nil {
				log.Panicf("Parse config file %v failed: %s \n", cfgFile, err)
			}
			if panelConfig.LogConfig.Level == "debug" {
				log.SetReportCaller(true)
			}
			p.Start()
			lastTime = time.Now()
		}
	})

	p.Start()
	defer p.Close()
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
