package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/curve25519"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "x25519",
		Short: "Generate key pair for x25519 key exchange",
		Run: func(cmd *cobra.Command, args []string) {
			if err := x25519(); err != nil {
				fmt.Println(err)
			}
		},
	})
}

func x25519() error {
	var publicKey []byte
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return err
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
