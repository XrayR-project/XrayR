package main

import (
	"log"

	"github.com/XrayR-project/XrayR/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
