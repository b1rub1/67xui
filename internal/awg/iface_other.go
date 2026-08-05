//go:build !linux

package awg

import "fmt"

func bringUp(name string, port int, listen string, settings *Settings) error {
	return fmt.Errorf("awg: interface management is only supported on Linux (got non-linux build)")
}

func bringDown(name, address string) error {
	return fmt.Errorf("awg: interface management is only supported on Linux")
}

func syncPeers(name string, peers []PeerEntry) error {
	return fmt.Errorf("awg: peer sync is only supported on Linux")
}

func setupForwarding(iface, address string) {}

func teardownForwarding(iface, address string) {}
