package main

import (
	_ "embed"

	"takeoverx/cmd"
)

//go:embed fingerprints/services.json
var fingerprintsData []byte

func main() {
	cmd.FingerprintsData = fingerprintsData
	cmd.Execute()
}
