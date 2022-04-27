package controller

import (
	"fmt"
	"strings"

	"github.com/XrayR-project/XrayR/api"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
)

var AEADMethod = []shadowsocks.CipherType{shadowsocks.CipherType_AES_128_GCM, shadowsocks.CipherType_AES_256_GCM, shadowsocks.CipherType_CHACHA20_POLY1305, shadowsocks.CipherType_XCHACHA20_POLY1305}

func (c *Controller) buildVmessUser(userInfo *[]api.UserInfo, serverAlterID uint16) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       user.UUID,
			AlterIds: serverAlterID,
			Security: "auto",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return users
}

func (c *Controller) buildVlessUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vlessAccount := &vless.Account{
			Id:   user.UUID,
			Flow: "xtls-rprx-direct",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return users
}

func (c *Controller) buildTrojanUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		trojanAccount := &trojan.Account{
			Password: user.UUID,
			Flow:     "xtls-rprx-direct",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return users
}

func (c *Controller) buildSSUser(userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, 0)

	cypherMethod := cipherFromString(method)
	for _, user := range *userInfo {
		ssAccount := &shadowsocks.Account{
			Password:   user.Passwd,
			CipherType: cypherMethod,
		}
		users = append(users, &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(ssAccount),
		})
	}
	return users
}

func (c *Controller) buildSSPluginUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, 0)

	for _, user := range *userInfo {
		// Check if the cypher method is AEAD
		cypherMethod := cipherFromString(user.Method)
		for _, aeadMethod := range AEADMethod {
			if aeadMethod == cypherMethod {
				ssAccount := &shadowsocks.Account{
					Password:   user.Passwd,
					CipherType: cypherMethod,
				}
				users = append(users, &protocol.User{
					Level:   0,
					Email:   c.buildUserTag(&user),
					Account: serial.ToTypedMessage(ssAccount),
				})
			}
		}

	}
	return users
}

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func (c *Controller) buildUserTag(user *api.UserInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)
}
