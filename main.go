package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/XrayR-project/XrayR/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
