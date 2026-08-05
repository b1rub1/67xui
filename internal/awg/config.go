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
	MTU       int    `json:"mtu"`       // tunnel MTU; 0 → use default 1420
	DNS       string `json:"dns"`       // client-side DNS, e.g. "1.1.1.1"

	Params Params `json:"params"` // AWG 2.0 obfuscation parameters

	// Peers is the list of client entries stored inline in settings, following
	// the same pattern as the WireGuard inbound in 3x-ui. This slice is
	// serialised as the "peers" JSON array and used both when writing the server
	// interface config and when generating per-client .conf files.
	Peers []PeerEntry `json:"peers"`
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

// ServerConf renders the AWG interface .conf that awg-quick / awg-tools will
// apply to the kernel or userspace interface. Only the [Interface] section is
// rendered here; peers are applied separately via UAPI so hot-add/remove works
// without restarting the whole interface.
func ServerConf(port int, settings *Settings) string {
	var b strings.Builder
	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", settings.SecretKey)
	fmt.Fprintf(&b, "Address = %s\n", settings.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	writeParams(&b, &settings.Params)
	return b.String()
}

// ClientConf renders the full [Interface]+[Peer] .conf for a single client.
// This is the file that gets base64url-encoded and embedded in the
// amneziawg:// subscription link.
func ClientConf(serverHost string, serverPort int, serverPubKey string, settings *Settings, peer *PeerEntry) string {
	var b strings.Builder
	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1420
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
