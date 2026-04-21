package main

import (
	"os"

	"github.com/cleverg0d/cyberheap/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
