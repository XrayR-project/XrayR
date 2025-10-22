package cmd

import (
	"crypto/aes"
	"crypto/cipher"
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
	key     string // 新增 key 变量
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
	rootCmd.PersistentFlags().StringVarP(&key, "key", "k", "", "AES-256-CFB key (数字串即可，自动填充32字节)")
}

// decryptAES256CFB 解密函数
func decryptAES256CFB(encFile string, keyStr string) ([]byte, error) {
	// 读取加密文件
	data, err := ioutil.ReadFile(encFile)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %v", err)
	}

	// 填充 key 到 32 字节
	keyBytes := []byte(keyStr)
	if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	} else if len(keyBytes) < 32 {
		pad := make([]byte, 32-len(keyBytes))
		keyBytes = append(keyBytes, pad...)
	}

	// IV 使用全 0（测试用）
	iv := make([]byte, aes.BlockSize)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create cipher failed: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
}

func getConfig() *viper.Viper {
	config := viper.New()

	if cfgFile != "" && key != "" {
		// 解密 config
		decBytes, err := decryptAES256CFB(cfgFile, key)
		if err != nil {
			log.Panicf("Failed to decrypt config: %v", err)
		}
		// 写入临时文件
		tmpFile := "config.yml.tmp"
		if err := ioutil.WriteFile(tmpFile, decBytes, 0644); err != nil {
			log.Panicf("Write temp config failed: %v", err)
		}
		cfgFile = tmpFile
	}

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

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig()
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

func showVersion() {
	fmt.Println("XrayR 0.9.5 (A Xray backend that supports many panels)")
}
