package cmd

import (
	"fmt"
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
				log.Error("XrayR failed to start")
				os.Exit(1)
			}
		},
	}
)

func init() {
	// Configure global logger time format.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05.000000",
	})

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
}

func getConfig() (*viper.Viper, error) {
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
		// Set ASSET Path and Config Path for XrayR
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config file error: %w", err)
	}

	config.WatchConfig() // Watch the config

	return config, nil
}

func run() error {
	showVersion()

	config, err := getConfig()
	if err != nil {
		return err
	}
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	if panelConfig.LogConfig != nil && panelConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	} else {
		log.SetReportCaller(false)
	}

	// Create initial panel instance.
	p := panel.New(panelConfig)
	lastTime := time.Now()
	config.OnConfigChange(func(e fsnotify.Event) {
		// Discard events received within a short period of time after receiving an event.
		if !time.Now().After(lastTime.Add(3 * time.Second)) {
			return
		}

		// Hot reload function
		fmt.Println("Config file changed:", e.Name)

		// To avoid stopping running services due to temporary write/parse errors, read and parse
		// the updated config into a new viper instance first, and only swap when successful.
		newPanelConfig := &panel.Config{}
		newViper := viper.New()
		if e.Name != "" {
			newViper.SetConfigFile(e.Name)
		} else if cfgFile != "" {
			newViper.SetConfigFile(cfgFile)
		} else {
			// Fallback to the same search logic as getConfig
			newViper.SetConfigName("config")
			newViper.SetConfigType("yml")
			newViper.AddConfigPath(".")
		}

		if err := newViper.ReadInConfig(); err != nil {
			log.Errorf("Hot reload: failed to read new config file %s: %v; keeping existing configuration", e.Name, err)
			return
		}
		if err := newViper.Unmarshal(newPanelConfig); err != nil {
			log.Errorf("Hot reload: failed to parse new config file %s: %v; keeping existing configuration", e.Name, err)
			return
		}
		if len(newPanelConfig.NodesConfig) == 0 {
			log.Warnf("Hot reload: new config file %s contains no Nodes; ignoring reload to avoid stopping running services", e.Name)
			return
		}

		// Swap to the new config and panel instance after successful parse.
		if err := p.Close(); err != nil {
			log.Error("Hot reload: failed to close old panel")
		}
		// Delete old instance and trigger GC
		runtime.GC()

		if newPanelConfig.LogConfig != nil && newPanelConfig.LogConfig.Level == "debug" {
			log.SetReportCaller(true)
		} else {
			log.SetReportCaller(false)
		}

		panelConfig = newPanelConfig
		p = panel.New(panelConfig)

		if err := p.Start(); err != nil {
			log.Error("Hot reload: failed to start new panel")
			return
		}
		lastTime = time.Now()
	})

	if err := p.Start(); err != nil {
		return fmt.Errorf("failed to start panel: %w", err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			log.Error("Failed to close panel")
		}
	}()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
