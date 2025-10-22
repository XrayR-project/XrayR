package cmd

import (
	"bytes"
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
	key     string
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
	rootCmd.PersistentFlags().StringVarP(&key, "key", "k", "", "Password for encrypted config file.")
}

// AES-256-CFB decrypt using password as key
func decryptAES256CFB(data []byte, password string) ([]byte, error) {
	hashedKey := make([]byte, 32)
	copy(hashedKey, []byte(password)) // 填充或截断为 32 字节
	block, err := aes.NewCipher(hashedKey)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := make([]byte, aes.BlockSize) // IV 全 0
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
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
	} else {
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")
	}

	if strings.HasSuffix(cfgFile, ".enc") {
		// 加密文件读取
		if key == "" {
			log.Panic("Encrypted config requires --key")
		}
		encData, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			log.Panicf("Read encrypted config error: %s\n", err)
		}
		decrypted, err := decryptAES256CFB(encData, key)
		if err != nil {
			log.Panicf("Decrypt config failed: %s\n", err)
		}
		fmt.Println("Decrypted config content:\n", string(decrypted))
		// 临时写入 buffer 并让 viper 读取
		if err := config.ReadConfig(bytes.NewReader(decrypted)); err != nil {
			log.Panicf("Parse decrypted config failed: %s\n", err)
		}
	} else {
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

	runtime.GC()
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
