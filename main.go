package main

import (
	_ "embed"

	"github.com/0xStr1k3r/TakeoverX/cmd"
)

//go:embed fingerprints/services.json
var fingerprintsData []byte

func main() {
	cmd.FingerprintsData = fingerprintsData
	cmd.Execute()
}
