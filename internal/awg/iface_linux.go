//go:build linux

package awg

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// confDir returns the directory where we write per-interface .conf files,
// alongside the Xray binary — matching the mtproto pattern.
func confDir() string {
	return filepath.Join(config.GetBinFolderPath(), "awg")
}

func confPath(name string) string {
	return filepath.Join(confDir(), name+".conf")
}

// bringUp creates and configures a new AWG interface. It tries (in order):
//  1. awg-quick up <conf>   — if awg-quick is in PATH
//  2. Manual ip link + awg setconf via UAPI
func bringUp(name string, port int, listen string, settings *Settings) error {
	if err := os.MkdirAll(confDir(), 0700); err != nil {
		return fmt.Errorf("awg: mkdir conf dir: %w", err)
	}
	serverConf := ServerConf(port, settings)

	// Write all enabled peers into the server conf so awg-quick can apply them.
	var b strings.Builder
	b.WriteString(serverConf)
	for _, peer := range settings.EffectivePeers() {
		if !peerIsActive(peer) {
			continue
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		if peer.PreSharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PreSharedKey)
		}
		if len(peer.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
		}
		if peer.KeepAlive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.KeepAlive)
		}
	}

	path := confPath(name)
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("awg: write conf: %w", err)
	}

	if awgQuickPath, err := exec.LookPath("awg-quick"); err == nil {
		// Prefer userspace implementation in containers where the amneziawg
		// kernel module is almost never present. awg-quick falls back to this
		// automatically when `ip link add type amneziawg` fails, but setting
		// the env makes the intent explicit and avoids a noisy error first.
		cmd := exec.Command(awgQuickPath, "up", path)
		cmd.Env = append(os.Environ(), "WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("awg-quick up: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
		setupForwarding(name, settings.Address)
		return nil
	}

	// Fallback: bring the interface up manually.
	if err := bringUpManual(name, port, listen, settings); err != nil {
		return err
	}
	setupForwarding(name, settings.Address)
	return nil
}

// bringDown tears down an AWG interface, preferring awg-quick down.
func bringDown(name, address string) error {
	path := confPath(name)
	teardownForwarding(name, address)
	if awgQuickPath, err := exec.LookPath("awg-quick"); err == nil {
		if err := runCmd(awgQuickPath, "down", path); err != nil {
			logger.Warning("awg: awg-quick down failed, trying ip link del:", err)
		} else {
			_ = os.Remove(path)
			return nil
		}
	}
	if err := runCmd("ip", "link", "delete", name); err != nil {
		return fmt.Errorf("awg: ip link delete %s: %w", name, err)
	}
	_ = os.Remove(path)
	return nil
}

// syncPeers hot-applies the peer list to a running interface via UAPI.
// Each active peer is upserted individually — we do NOT use replace_peers=true
// because amneziawg-go clears session state when the peer set is replaced,
// which drops every live client connection every 10 seconds (cadenceAWG).
// Peers that should be removed are passed via the `remove` slice and get an
// explicit remove=true message so they are torn down cleanly.
func syncPeers(name string, peers []PeerEntry) error {
	return syncPeersDiff(name, peers, nil)
}

// syncPeersDiff upserts `peers` and removes `removePubKeys` from the interface.
func syncPeersDiff(name string, peers []PeerEntry, removePubKeys []string) error {
	sockPath := resolveUAPISocket(name)
	if sockPath == "" {
		return nil
	}
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("awg: uapi connect %s: %w", sockPath, err)
	}
	defer conn.Close()

	var cmd strings.Builder
	cmd.WriteString("set=1\n")

	// Remove peers that are no longer wanted.
	for _, pubKey := range removePubKeys {
		hex := hexKey(pubKey)
		if hex == "" {
			continue
		}
		fmt.Fprintf(&cmd, "public_key=%s\n", hex)
		cmd.WriteString("remove=true\n")
	}

	// Upsert active peers without replace_peers so existing sessions survive.
	for _, peer := range peers {
		if !peerIsActive(peer) {
			continue
		}
		fmt.Fprintf(&cmd, "public_key=%s\n", hexKey(peer.PublicKey))
		if peer.PreSharedKey != "" {
			fmt.Fprintf(&cmd, "preshared_key=%s\n", hexKey(peer.PreSharedKey))
		}
		// Replace the allowed-IPs set for this peer.
		cmd.WriteString("replace_allowed_ips=true\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&cmd, "allowed_ip=%s\n", ip)
		}
		if peer.KeepAlive > 0 {
			fmt.Fprintf(&cmd, "persistent_keepalive_interval=%d\n", peer.KeepAlive)
		}
	}
	cmd.WriteString("\n")

	if _, err := fmt.Fprint(conn, cmd.String()); err != nil {
		return fmt.Errorf("awg: uapi write: %w", err)
	}
	return readUAPIResponse(conn)
}

// bringUpManual tries to create a WireGuard-type interface via ip-link and
// configure it through the UAPI socket that amneziawg-go exposes.
func bringUpManual(name string, port int, listen string, settings *Settings) error {
	// Try amneziawg kernel module first.
	if err := runCmd("ip", "link", "add", name, "type", "amneziawg"); err != nil {
		// Try wireguard as kernel fallback (won't have AWG obfuscation).
		logger.Warning("awg: amneziawg kernel module not available, trying wireguard:", err)
		if err2 := runCmd("ip", "link", "add", name, "type", "wireguard"); err2 != nil {
			return fmt.Errorf("awg: cannot create interface (no amneziawg/wireguard kernel module): %w", err2)
		}
	}
	if err := runCmd("ip", "link", "set", name, "up"); err != nil {
		return fmt.Errorf("awg: ip link set up: %w", err)
	}
	if settings.Address != "" {
		if err := runCmd("ip", "addr", "add", settings.Address, "dev", name); err != nil {
			logger.Warning("awg: ip addr add:", err)
		}
	}
	return nil
}

func uapiSocketPath(name string) string {
	// amneziawg-go and current amneziawg-tools use /var/run/amneziawg/.
	// Older builds used /var/run/amnezia/ — try both in syncPeers.
	return fmt.Sprintf("/var/run/amneziawg/%s.sock", name)
}

func resolveUAPISocket(name string) string {
	candidates := []string{
		fmt.Sprintf("/var/run/amneziawg/%s.sock", name),
		fmt.Sprintf("/var/run/amnezia/%s.sock", name),
		fmt.Sprintf("/var/run/wireguard/%s.sock", name),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// dumpPeers reads the live peer table for iface `name` via UAPI get=1.
// Returns nil when the socket is missing (interface not up).
func dumpPeers(name string) ([]peerDump, error) {
	sockPath := resolveUAPISocket(name)
	if sockPath == "" {
		return nil, nil
	}
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("awg: uapi connect %s: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := io.WriteString(conn, "get=1\n\n"); err != nil {
		return nil, fmt.Errorf("awg: uapi get write: %w", err)
	}
	return parsePeerDump(conn)
}

// setupForwarding enables IPv4 forwarding and installs FORWARD/MASQUERADE rules
// so AWG clients can reach the internet. Safe to call repeatedly.
func setupForwarding(iface, address string) {
	subnet := tunnelSubnet(address)
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	if iface != "" {
		iptablesEnsureForward([]string{"-i", iface, "-j", "ACCEPT"})
		iptablesEnsureForward([]string{"-o", iface, "-j", "ACCEPT"})
	}
	if subnet != "" {
		iptablesEnsure([]string{"nat", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE"})
	}
}

func teardownForwarding(iface, address string) {
	subnet := tunnelSubnet(address)
	if iface != "" {
		_ = exec.Command("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT").Run()
	}
	if subnet != "" {
		_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run()
	}
}

// iptablesEnsureForward inserts a FORWARD rule at the head of the chain so
// it runs before UFW's ufw-before-forward DROP/reject jumps.
func iptablesEnsureForward(args []string) {
	check := append([]string{"-C", "FORWARD"}, args...)
	insert := append([]string{"-I", "FORWARD", "1"}, args...)
	if err := exec.Command("iptables", check...).Run(); err == nil {
		return
	}
	if out, err := exec.Command("iptables", insert...).CombinedOutput(); err != nil {
		logger.Warning("awg: iptables", strings.Join(insert, " "), ":", err, string(out))
	}
}

// iptablesEnsure adds a rule only when it is not already present.
// tableArgs is either ["FORWARD", ...] or ["nat", "POSTROUTING", ...].
func iptablesEnsure(args []string) {
	var check, add []string
	if len(args) > 0 && args[0] == "nat" {
		check = append([]string{"-t", "nat", "-C"}, args[1:]...)
		add = append([]string{"-t", "nat", "-A"}, args[1:]...)
	} else {
		check = append([]string{"-C"}, args...)
		add = append([]string{"-A"}, args...)
	}
	if err := exec.Command("iptables", check...).Run(); err == nil {
		return
	}
	if out, err := exec.Command("iptables", add...).CombinedOutput(); err != nil {
		logger.Warning("awg: iptables", strings.Join(add, " "), ":", err, string(out))
	}
}
