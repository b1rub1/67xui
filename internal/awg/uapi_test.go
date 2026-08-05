package awg

import (
	"strings"
	"testing"
)

func TestParsePeerDump(t *testing.T) {
	raw := "" +
		"private_key=aabb\n" +
		"listen_port=51820\n" +
		"public_key=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n" +
		"endpoint=1.2.3.4:1234\n" +
		"allowed_ip=10.66.0.2/32\n" +
		"last_handshake_time_sec=1700000000\n" +
		"rx_bytes=1000\n" +
		"tx_bytes=2000\n" +
		"public_key=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\n" +
		"rx_bytes=5\n" +
		"tx_bytes=6\n" +
		"last_handshake_time_sec=0\n" +
		"errno=0\n" +
		"\n"
	peers, err := parsePeerDump(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parsePeerDump: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	if peers[0].RxBytes != 1000 || peers[0].TxBytes != 2000 {
		t.Fatalf("peer0 counters = %+v", peers[0])
	}
	if peers[0].LastHandshakeSec != 1700000000 {
		t.Fatalf("peer0 handshake = %d", peers[0].LastHandshakeSec)
	}
	if peers[1].RxBytes != 5 || peers[1].LastHandshakeSec != 0 {
		t.Fatalf("peer1 = %+v", peers[1])
	}
}

func TestParsePeerDumpErrno(t *testing.T) {
	raw := "errno=1\n\n"
	if _, err := parsePeerDump(strings.NewReader(raw)); err == nil {
		t.Fatal("expected errno error")
	}
}
