package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/curve25519"
)

var (
	priKey    string
	x25519Cmd = &cobra.Command{
		Use:   "x25519",
		Short: "Generate key pair for x25519 key exchange",
		Run: func(cmd *cobra.Command, args []string) {
			if err := x25519(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	x25519Cmd.PersistentFlags().StringVarP(&priKey, "input", "i", "", "Input private key (base64.RawURLEncoding)")
	rootCmd.AddCommand(x25519Cmd)
}

func x25519() error {
	privateKey := make([]byte, curve25519.ScalarSize)

	if priKey == "" {
		if _, err := rand.Read(privateKey); err != nil {
			return err
		}
	} else {
		p, err := base64.RawURLEncoding.DecodeString(priKey)
		if err != nil {
			return err
		}
		if len(p) != curve25519.ScalarSize {
			return errors.New("invalid private key")
		}
		privateKey = p
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}

	output := fmt.Sprintf("Private key: %v\nPublic key: %v",
		base64.RawURLEncoding.EncodeToString(privateKey),
		base64.RawURLEncoding.EncodeToString(publicKey))
	fmt.Println(output)

	return nil
}
