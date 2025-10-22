package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
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
	rootCmd.PersistentFlags().String("key", "", "Key to decrypt the encrypted config file")
}

func getConfig() *viper.Viper {
	config := viper.New()

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
	}

	// 获取 key 参数
	key := ""
	if rootCmd.Flags().Changed("key") {
		key, _ = rootCmd.Flags().GetString("key")
	}

	if key != "" && strings.HasSuffix(cfgFile, ".enc") {
		fmt.Println("INFO: Encrypted config detected, decrypting...")
		decrypted, err := decryptAES256CFBFile(cfgFile, key)
		if err != nil {
			log.Panicf("Failed to decrypt config: %v", err)
		}

		tmpFile := path.Join(os.TempDir(), "XrayR_config_decrypted.yml")
		if err := os.WriteFile(tmpFile, decrypted, 0644); err != nil {
			log.Panicf("Failed to write temp config file: %v", err)
		}
		cfgFile = tmpFile
		config.SetConfigFile(cfgFile)
	} else if cfgFile != "" {
		config.SetConfigFile(cfgFile)
	} else {
		// 默认配置
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")
	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig()
	return config
}

// AES-256-CFB 解密函数
func decryptAES256CFBFile(filename, password string) ([]byte, error) {
	encData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if len(encData) < 16 {
		return nil, errors.New("invalid encrypted file")
	}

	// OpenSSL 默认加盐格式：Salted__ + 8 bytes salt
	saltPrefix := []byte("Salted__")
	if string(encData[:8]) != string(saltPrefix) {
		return nil, errors.New("missing Salted__ header")
	}
	salt := encData[8:16]
	cipherText := encData[16:]

	key, iv := evpBytesToKey([]byte(password), salt, 32, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(cipherText))
	stream.XORKeyStream(decrypted, cipherText)

	return decrypted, nil
}

// 兼容 OpenSSL EVP_BytesToKey
func evpBytesToKey(password, salt []byte, keyLen, ivLen int) ([]byte, []byte) {
	var keyiv []byte
	var prev []byte
	for len(keyiv) < keyLen+ivLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		keyiv = append(keyiv, prev...)
	}
	return keyiv[:keyLen], keyiv[keyLen : keyLen+ivLen]
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

// 可选：显示版本
func showVersion() {
	fmt.Println("XrayR 0.9.5 (A Xray backend that supports many panels)")
}
