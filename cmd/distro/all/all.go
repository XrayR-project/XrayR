package all

import (
	// The following are necessary as they register handlers in their init functions.

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/XrayR-project/XrayR/app/mydispatcher"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xtls/xray-core/app/commander"
	_ "github.com/xtls/xray-core/app/log/command"
	_ "github.com/xtls/xray-core/app/proxyman/command"
	_ "github.com/xtls/xray-core/app/stats/command"

	// Other optional features.
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/metrics"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/reverse"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// Transports
	_ "github.com/xtls/xray-core/transport/internet/http"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"
	_ "github.com/xtls/xray-core/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/main/toml"
	_ "github.com/xtls/xray-core/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xtls/xray-core/main/confloader/external"

	// Commands
	_ "github.com/xtls/xray-core/main/commands/all"
)
