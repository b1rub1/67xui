// Package awg manages AmneziaWG 2.0 sidecar interfaces alongside the panel's
// Xray process. Each AWG inbound maps to one network interface (kernel or
// userspace) and is configured entirely outside of Xray via awg-quick / UAPI.
package awg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Params holds all AWG 2.0 obfuscation parameters for one interface.
// They are stored as JSON in the Inbound.Settings column alongside the
// WireGuard key material and are sent to the AWG daemon via UAPI on startup
// and peer reconciliation.
type Params struct {
	// Junk packets — sent before the real handshake to confuse DPI.
	Jc   uint32 `json:"jc"`   // count (1-128)
	Jmin uint32 `json:"jmin"` // min size bytes (40-1000)
	Jmax uint32 `json:"jmax"` // max size bytes (Jmin..1280)

	// Message paddings — extra zero bytes appended to specific packet types.
	S1 uint32 `json:"s1"` // HandshakeInitiation extra bytes (15-150)
	S2 uint32 `json:"s2"` // HandshakeResponse extra bytes   (15-150)
	S3 uint32 `json:"s3"` // CookieReply extra bytes         (5-40)
	S4 uint32 `json:"s4"` // Transport extra bytes           (1-32)

	// Magic headers — replace WireGuard's fixed 4-byte message-type field so
	// packets carry no recognizable WireGuard signature.
	H1 uint32 `json:"h1"` // replaces WireGuard type 1 (HandshakeInitiation)
	H2 uint32 `json:"h2"` // replaces WireGuard type 2 (HandshakeResponse)
	H3 uint32 `json:"h3"` // replaces WireGuard type 3 (CookieReply)
	H4 uint32 `json:"h4"` // replaces WireGuard type 4 (Transport)

	// Init packet chain (AWG 2.0) — segment descriptors for mimicking other
	// UDP protocols (QUIC, DNS, SIP) during the handshake initiation.
	// Format: "<r N>" means N random bytes; other vendor-specific formats exist.
	I1 string `json:"i1"`
	I2 string `json:"i2"`
	I3 string `json:"i3"`
	I4 string `json:"i4"`
	I5 string `json:"i5"`
}

// GenerateParams creates a fresh set of AWG 2.0 obfuscation parameters with
// cryptographically random values that satisfy the AWG 2.0 protocol constraints.
func GenerateParams() (Params, error) {
	var p Params
	var err error

	if p.Jc, err = randRange(3, 8); err != nil {
		return p, fmt.Errorf("awg params: jc: %w", err)
	}
	if p.Jmin, err = randRange(50, 200); err != nil {
		return p, fmt.Errorf("awg params: jmin: %w", err)
	}
	jmaxMax := p.Jmin + 800
	if jmaxMax > 1250 {
		jmaxMax = 1250
	}
	if p.Jmax, err = randRange(p.Jmin+50, jmaxMax); err != nil {
		return p, fmt.Errorf("awg params: jmax: %w", err)
	}

	if p.S1, err = randRange(15, 100); err != nil {
		return p, fmt.Errorf("awg params: s1: %w", err)
	}
	if p.S2, err = randRange(15, 100); err != nil {
		return p, fmt.Errorf("awg params: s2: %w", err)
	}
	if p.S3, err = randRange(5, 30); err != nil {
		return p, fmt.Errorf("awg params: s3: %w", err)
	}
	if p.S4, err = randRange(1, 20); err != nil {
		return p, fmt.Errorf("awg params: s4: %w", err)
	}

	// H1-H4 must be unique and must not overlap with standard WireGuard
	// message types (1-4) to avoid ambiguity in both directions.
	used := make(map[uint32]bool, 4)
	for _, hp := range []*uint32{&p.H1, &p.H2, &p.H3, &p.H4} {
		for {
			var b [4]byte
			if _, err := rand.Read(b[:]); err != nil {
				return p, fmt.Errorf("awg params: h-value: %w", err)
			}
			v := binary.LittleEndian.Uint32(b[:])
			if v < 5 || used[v] {
				continue
			}
			used[v] = true
			*hp = v
			break
		}
	}

	// I1-I5 (AWG 2.0 init-chain) are intentionally left empty.
	// The "<r N>" descriptor format is interpreted at daemon startup to produce
	// random bytes, but the *client* app reads the same descriptor and generates
	// *different* random bytes — the two sides never match, so the handshake
	// always fails. Leaving I1-I5 empty disables the init-chain (AWG 1.0 mode)
	// which AmneziaVPN fully supports via the Jc/S/H obfuscation parameters.

	return p, nil
}

func randRange(min, max uint32) (uint32, error) {
	if min >= max {
		return min, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + uint32(n.Int64()), nil
}
