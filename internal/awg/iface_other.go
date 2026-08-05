//go:build !linux

package awg

import "fmt"

func bringUp(name string, port int, listen string, settings *Settings) error {
	return fmt.Errorf("awg: interface management is only supported on Linux (got non-linux build)")
}

func bringDown(name string) error {
	return fmt.Errorf("awg: interface management is only supported on Linux")
}

func syncPeers(name string, peers []PeerEntry) error {
	return fmt.Errorf("awg: peer sync is only supported on Linux")
}
