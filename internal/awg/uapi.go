package awg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

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
