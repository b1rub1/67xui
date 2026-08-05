package awg

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Settings is the JSON structure stored in Inbound.Settings for an AWG inbound.
// It mirrors the WireGuard settings shape for common fields so the same client
// model (PrivateKey, PublicKey, AllowedIPs, PreSharedKey, KeepAlive) can be
// reused without changes to the database schema.
type Settings struct {
	SecretKey string `json:"secretKey"` // server private key (base64)
	PublicKey string `json:"publicKey"` // server public key (base64, derived)
	Address   string `json:"address"`   // server tunnel IP, e.g. "10.8.0.1/24"
	MTU       int    `json:"mtu"`       // tunnel MTU; 0 → use default 1100
	DNS       string `json:"dns"`       // client-side DNS, e.g. "1.1.1.1"

	Params Params `json:"params"` // AWG 2.0 obfuscation parameters

	// Clients is the panel source of truth (same shape as WireGuard /
	// VLESS / …). Peers is kept for backward compatibility with older
	// settings JSON that stored the list under "peers"; EffectivePeers
	// prefers Clients when present.
	Clients []PeerEntry `json:"clients"`
	Peers   []PeerEntry `json:"peers"`
}

// EffectivePeers returns the peer list that should be applied to the
// running interface. The panel always writes under "clients"; older
// installs may still have "peers".
func (s *Settings) EffectivePeers() []PeerEntry {
	if len(s.Clients) > 0 {
		return s.Clients
	}
	return s.Peers
}

// PeerEntry is one client/peer stored inside Settings.Peers.
type PeerEntry struct {
	Email        string   `json:"email"`
	PrivateKey   string   `json:"privateKey"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
	KeepAlive    int      `json:"keepAlive,omitempty"`
	Enable       bool     `json:"enable"`
}

// peerIsActive reports whether a peer should be programmed into the interface.
func peerIsActive(p PeerEntry) bool {
	return p.PublicKey != "" && p.Enable
}

// ServerConf renders the AWG interface .conf that awg-quick / awg-tools will
// apply to the kernel or userspace interface. Only the [Interface] section is
// rendered here; peers are applied separately via UAPI so hot-add/remove works
// without restarting the whole interface.
//
// PostUp/PostDown enable IPv4 forwarding and NAT so client traffic can reach
// the internet (without this, handshake/ping to the tunnel works but there is
// no internet access).
func ServerConf(port int, settings *Settings) string {
	var b strings.Builder
	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1100
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", settings.SecretKey)
	fmt.Fprintf(&b, "Address = %s\n", settings.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	writeParams(&b, &settings.Params)

	subnet := tunnelSubnet(settings.Address)
	if subnet != "" {
		// %i is expanded by awg-quick/wg-quick to the interface name.
		fmt.Fprintf(&b, "PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -C FORWARD -i %%i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %%i -j ACCEPT; iptables -C FORWARD -o %%i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o %%i -j ACCEPT; iptables -t nat -C POSTROUTING -s %s ! -d %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -d %s -j MASQUERADE\n", subnet, subnet, subnet, subnet)
		fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -i %%i -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o %%i -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s %s ! -d %s -j MASQUERADE 2>/dev/null || true\n", subnet, subnet)
	}
	return b.String()
}

// tunnelSubnet turns a host address like "10.66.0.1/24" into the network
// prefix "10.66.0.0/24" used as the MASQUERADE source. Returns "" when the
// address is missing or unparsable.
func tunnelSubnet(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	// Prefer netip via a small parse without pulling heavy deps into this file —
	// Address is always written by the panel as host/prefix.
	var ipPart, maskPart string
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		ipPart, maskPart = addr[:i], addr[i+1:]
	} else {
		return ""
	}
	parts := strings.Split(ipPart, ".")
	if len(parts) != 4 || maskPart == "" {
		// IPv6 or unexpected — fall back to the original prefix as-is.
		return addr
	}
	switch maskPart {
	case "24":
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	case "16":
		return parts[0] + "." + parts[1] + ".0.0/16"
	case "8":
		return parts[0] + ".0.0.0/8"
	case "32":
		// A /32 server address can't NAT a whole client pool; use /24 of the same octet.
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	default:
		return addr
	}
}

// ClientConf renders the full [Interface]+[Peer] .conf for a single client.
// This is the file that gets base64url-encoded and embedded in the
// amneziawg:// subscription link.
func ClientConf(serverHost string, serverPort int, serverPubKey string, settings *Settings, peer *PeerEntry) string {
	var b strings.Builder
	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1100
	}
	dns := settings.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	if len(peer.AllowedIPs) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", peer.AllowedIPs[0])
	}
	fmt.Fprintf(&b, "DNS = %s\n", dns)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	writeParams(&b, &settings.Params)

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPubKey)
	if peer.PreSharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PreSharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", serverHost, serverPort)
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	ka := peer.KeepAlive
	if ka <= 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	return b.String()
}

// ClientConfBase64URL returns ClientConf encoded in URL-safe base64 (no padding)
// ready for embedding in an amneziawg:// URI.
func ClientConfBase64URL(serverHost string, serverPort int, serverPubKey string, settings *Settings, peer *PeerEntry) string {
	raw := ClientConf(serverHost, serverPort, serverPubKey, settings, peer)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// AmneziaWGLink builds the amneziawg://<base64url-conf>#Name URI that INCY
// (and other AmneziaVPN clients) accept in subscription bodies.
func AmneziaWGLink(serverHost string, serverPort int, serverPubKey string, settings *Settings, peer *PeerEntry, name string) string {
	b64 := ClientConfBase64URL(serverHost, serverPort, serverPubKey, settings, peer)
	return fmt.Sprintf("amneziawg://%s#%s", b64, name)
}

// writeParams writes the AWG 2.0 obfuscation parameters into the .conf writer.
// Parameters are always written; zero values are written as 0 so the daemon
// can distinguish "explicitly set to 0" from "not present".
func writeParams(b *strings.Builder, p *Params) {
	fmt.Fprintf(b, "Jc = %d\n", p.Jc)
	fmt.Fprintf(b, "Jmin = %d\n", p.Jmin)
	fmt.Fprintf(b, "Jmax = %d\n", p.Jmax)
	fmt.Fprintf(b, "S1 = %d\n", p.S1)
	fmt.Fprintf(b, "S2 = %d\n", p.S2)
	fmt.Fprintf(b, "S3 = %d\n", p.S3)
	fmt.Fprintf(b, "S4 = %d\n", p.S4)
	fmt.Fprintf(b, "H1 = %d\n", p.H1)
	fmt.Fprintf(b, "H2 = %d\n", p.H2)
	fmt.Fprintf(b, "H3 = %d\n", p.H3)
	fmt.Fprintf(b, "H4 = %d\n", p.H4)
	if p.I1 != "" {
		fmt.Fprintf(b, "I1 = %s\n", p.I1)
		fmt.Fprintf(b, "I2 = %s\n", p.I2)
		fmt.Fprintf(b, "I3 = %s\n", p.I3)
		fmt.Fprintf(b, "I4 = %s\n", p.I4)
		fmt.Fprintf(b, "I5 = %s\n", p.I5)
	}
}
