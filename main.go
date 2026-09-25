package main

import (
	"github.com/cerberauth/iamigrate/cmd"
	"github.com/cerberauth/iamigrate/pkg/httpx"
)

// version is set at build time via .goreleaser.yaml's -X main.version=...
// ldflag; it defaults to "dev" for local builds.
var version = "dev"

func main() {
	httpx.Version = version
	cmd.Execute()
}
