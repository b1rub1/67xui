package awg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// peerDump is one peer's live counters from a UAPI get=1 dump.
type peerDump struct {
	PublicKeyHex     string
	RxBytes          int64
	TxBytes          int64
	LastHandshakeSec int64
}

// parsePeerDump reads a WireGuard/AmneziaWG UAPI get=1 response into peerDump
// entries. The response is a sequence of key=value lines; a new peer starts
// when public_key= appears, and the dump ends on a blank line or errno=.
func parsePeerDump(r io.Reader) ([]peerDump, error) {
	var out []peerDump
	var cur *peerDump
	flush := func() {
		if cur != nil && cur.PublicKeyHex != "" {
			out = append(out, *cur)
		}
		cur = nil
	}

	scanner := bufio.NewScanner(r)
	// Peer dumps can be large with many allowed_ip lines; raise the limit.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			flush()
			cur = &peerDump{PublicKeyHex: strings.ToLower(val)}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(val, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(val, 10, 64)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshakeSec, _ = strconv.ParseInt(val, 10, 64)
			}
		case "errno":
			if val != "0" {
				return nil, fmt.Errorf("awg: UAPI get errno=%s", val)
			}
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("awg: UAPI get read: %w", err)
	}
	return out, nil
}

// hexKey converts a base64-encoded WireGuard key (standard or URL-safe) to the
// lowercase hex form that the WireGuard / AmneziaWG UAPI expects.
// Returns an empty string on decode failure so callers can skip bad entries.
func hexKey(b64 string) string {
	trimmed := strings.TrimRight(b64, "=")
	var raw []byte
	var err error
	if strings.ContainsAny(trimmed, "+/") {
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
	} else {
		raw, err = base64.RawURLEncoding.DecodeString(trimmed)
	}
	if err != nil || len(raw) != 32 {
		return ""
	}
	return hex.EncodeToString(raw)
}

// readUAPIResponse reads and validates the errno= response from the AWG UAPI
// socket. A non-zero errno means the kernel rejected the configuration.
func readUAPIResponse(conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "errno=") {
			code := strings.TrimPrefix(line, "errno=")
			if code != "0" {
				return fmt.Errorf("awg: UAPI error errno=%s", code)
			}
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("awg: UAPI read: %w", err)
	}
	return nil
}
