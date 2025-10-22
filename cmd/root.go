package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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
	keyStr  string

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
	rootCmd.PersistentFlags().StringVarP(&keyStr, "key", "k", "", "Decryption key for encrypted config.")
}

// decryptAES256CFBWithHash 使用 SHA256(key) 生成 32 字节 AES-256 key 解密配置
func decryptAES256CFBWithHash(cipherFile string, key string) ([]byte, error) {
	data, err := ioutil.ReadFile(cipherFile)
	if err != nil {
		return nil, err
	}

	hashKey := sha256.Sum256([]byte(key))       // 任意长度 key -> SHA256 -> 32 字节 key
	iv := bytes.Repeat([]byte{0}, aes.BlockSize) // IV 置零
	block, err := aes.NewCipher(hashKey[:])
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, data)

	return decrypted, nil
}

func getConfig() *viper.Viper {
	config := viper.New()

	if keyStr != "" {
		if cfgFile == "" {
			log.Panicf("Must specify encrypted config file with --config")
		}
		plainData, err := decryptAES256CFBWithHash(cfgFile, keyStr)
		if err != nil {
			log.Panicf("Failed to decrypt config: %s", err)
		}

		config.SetConfigType("yaml")
		if err := config.ReadConfig(bytes.NewReader(plainData)); err != nil {
			log.Panicf("Failed to read decrypted config: %s", err)
		}
	} else {
		// 普通未加密配置
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

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
