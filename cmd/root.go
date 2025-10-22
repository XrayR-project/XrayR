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
	rootCmd.PersistentFlags().StringVarP(&key, "key", "k", "", "Key for encrypted config file")
}

func getConfig() *viper.Viper {
	config := viper.New()
	if cfgFile == "" {
		cfgFile = "config.yml"
	}

	// 判断是否是加密文件
	data, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		log.Panicf("Failed to read config file: %v", err)
	}

	if key != "" {
		decrypted, err := decryptAES256CFB(data, []byte(key))
		if err != nil {
			log.Panicf("Failed to decrypt config: %v", err)
		}
		tmpFile := cfgFile + ".dec.tmp"
		if err := ioutil.WriteFile(tmpFile, decrypted, 0644); err != nil {
			log.Panicf("Failed to write temp decrypted config: %v", err)
		}
		cfgFile = tmpFile
	}

	configName := path.Base(cfgFile)
	configFileExt := path.Ext(cfgFile)
	configNameOnly := strings.TrimSuffix(configName, configFileExt)
	configPath := path.Dir(cfgFile)
	config.SetConfigName(configNameOnly)
	config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
	config.AddConfigPath(configPath)

	// 设置环境变量
	os.Setenv("XRAY_LOCATION_ASSET", configPath)
	os.Setenv("XRAY_LOCATION_CONFIG", configPath)

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig()
	return config
}

// AES-256-CFB 解密函数
func decryptAES256CFB(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key length must be 16, 24 or 32 bytes")
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
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
