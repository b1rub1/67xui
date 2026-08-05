package awg

import (
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// Instance describes the desired runtime state of one AWG interface.
// A single network interface (wg0, wg1, …) serves all active peers of one inbound.
type Instance struct {
	ID        int    // Inbound.Id
	Tag       string // Inbound.Tag, used as interface name
	Listen    string // bind address (empty → 0.0.0.0)
	Port      int
	Settings  *Settings
	NodeID    *int // nil for the local node
}

// ifaceName derives a short, kernel-valid interface name from the instance tag.
// Interface names on Linux are limited to 15 characters.
func (inst *Instance) ifaceName() string {
	name := "awg-" + inst.Tag
	if len(name) > 15 {
		name = fmt.Sprintf("awg%d", inst.ID)
	}
	return name
}

// Manager orchestrates the AWG interface lifecycle for all local AWG inbounds.
// It is intentionally symmetric with the mtproto.Manager so the InboundService
// can call Reconcile on both in the same job.
type Manager struct {
	mu      sync.Mutex
	running map[int]*runningIface // inbound ID → live interface handle
}

type runningIface struct {
	inst        Instance
	name        string // kernel interface name
	activePeers []string
	// last holds cumulative rx/tx counters keyed by client email from the
	// previous CollectTraffic scrape, used to compute per-poll deltas.
	last map[string]clientCounters
}

// Traffic is a per-client traffic delta scraped from an AWG interface.
type Traffic struct {
	Tag   string
	Email string
	Up    int64
	Down  int64
}

type clientCounters struct {
	up   int64
	down int64
}

// onlineHandshakeWindow is how recent a peer's last handshake must be to
// count as online. WireGuard's own convention is ~180s; we use the same so
// keepalive-only peers stay green between handshakes.
const onlineHandshakeWindow = 180

var globalManager = &Manager{
	running: make(map[int]*runningIface),
}

// GetManager returns the process-global AWG manager.
func GetManager() *Manager { return globalManager }

// Reconcile ensures that the set of running AWG interfaces matches `desired`.
// Interfaces not in `desired` are brought down; new ones are brought up;
// changed ones are reconfigured without a full restart where possible.
func (m *Manager) Reconcile(desired []Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	wantIDs := make(map[int]Instance, len(desired))
	for _, inst := range desired {
		wantIDs[inst.ID] = inst
	}

	// Stop interfaces that are no longer wanted.
	for id, ri := range m.running {
		if _, ok := wantIDs[id]; !ok {
			addr := ""
			if ri.inst.Settings != nil {
				addr = ri.inst.Settings.Address
			}
			if err := bringDown(ri.name, addr); err != nil {
				logger.Warning("awg: bring-down", ri.name, ":", err)
			}
			delete(m.running, id)
		}
	}

	// Start or reconfigure wanted interfaces.
	for _, inst := range desired {
		inst := inst
		ri, running := m.running[inst.ID]
		if !running {
			name := inst.ifaceName()
			if err := bringUp(name, inst.Port, inst.Listen, inst.Settings); err != nil {
				logger.Warning("awg: bring-up", name, ":", err)
				continue
			}
			if err := syncPeers(name, inst.Settings.EffectivePeers()); err != nil {
				logger.Warning("awg: sync-peers", name, ":", err)
			}
			m.running[inst.ID] = &runningIface{
				inst:        inst,
				name:        name,
				activePeers: activePubKeys(inst.Settings.EffectivePeers()),
				last:        make(map[string]clientCounters),
			}
		} else {
			// Already running — ensure NAT/forwarding is present and sync
			// only the diff (add/update active peers, remove disabled ones).
			// We do NOT use replace_peers=true to preserve live sessions.
			if inst.Settings != nil {
				setupForwarding(ri.name, inst.Settings.Address)
			}
			newPeers := inst.Settings.EffectivePeers()
			newKeys := activePubKeys(newPeers)
			removed := removedKeys(ri.activePeers, newKeys)
			if err := syncPeersDiff(ri.name, newPeers, removed); err != nil {
				logger.Warning("awg: sync-peers", ri.name, ":", err)
			}
			ri.inst = inst
			ri.activePeers = newKeys
		}
	}
	return nil
}

// StopAll tears down every managed interface. Called during panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ri := range m.running {
		addr := ""
		if ri.inst.Settings != nil {
			addr = ri.inst.Settings.Address
		}
		if err := bringDown(ri.name, addr); err != nil {
			logger.Warning("awg: stop-all bring-down", ri.name, ":", err)
		}
		delete(m.running, id)
	}
}

// ApplyPeers hot-syncs the peer list for one running interface without a full
// Reconcile. Called immediately after a client add/remove/enable-toggle, the
// same way applyLocalMtproto works for MTProto.
func (m *Manager) ApplyPeers(id int, peers []PeerEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ri, ok := m.running[id]
	if !ok {
		return fmt.Errorf("awg: inbound %d is not running", id)
	}
	newKeys := activePubKeys(peers)
	removed := removedKeys(ri.activePeers, newKeys)
	if err := syncPeersDiff(ri.name, peers, removed); err != nil {
		return err
	}
	ri.activePeers = newKeys
	return nil
}

// Ensure brings up (or hot-reconfigures) a single AWG instance without
// touching other running interfaces. Symmetric with mtproto.Manager.Ensure.
func (m *Manager) Ensure(inst Instance) error {
	if inst.Settings == nil {
		return fmt.Errorf("awg: inbound %d has no settings", inst.ID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	ri, running := m.running[inst.ID]
	if !running {
		name := inst.ifaceName()
		if err := bringUp(name, inst.Port, inst.Listen, inst.Settings); err != nil {
			return err
		}
		if err := syncPeers(name, inst.Settings.EffectivePeers()); err != nil {
			logger.Warning("awg: sync-peers", name, ":", err)
		}
		m.running[inst.ID] = &runningIface{
			inst:        inst,
			name:        name,
			activePeers: activePubKeys(inst.Settings.EffectivePeers()),
			last:        make(map[string]clientCounters),
		}
		return nil
	}
	newPeers := inst.Settings.EffectivePeers()
	newKeys := activePubKeys(newPeers)
	removed := removedKeys(ri.activePeers, newKeys)
	if err := syncPeersDiff(ri.name, newPeers, removed); err != nil {
		return err
	}
	setupForwarding(ri.name, inst.Settings.Address)
	ri.inst = inst
	ri.activePeers = newKeys
	return nil
}

// activePubKeys returns the public keys of all active peers.
func activePubKeys(peers []PeerEntry) []string {
	keys := make([]string, 0, len(peers))
	for _, p := range peers {
		if peerIsActive(p) {
			keys = append(keys, p.PublicKey)
		}
	}
	return keys
}

// removedKeys returns keys that were in prev but are not in next.
func removedKeys(prev, next []string) []string {
	nextSet := make(map[string]struct{}, len(next))
	for _, k := range next {
		nextSet[k] = struct{}{}
	}
	var removed []string
	for _, k := range prev {
		if _, ok := nextSet[k]; !ok {
			removed = append(removed, k)
		}
	}
	return removed
}

// Remove tears down the AWG interface for one inbound id.
func (m *Manager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ri, ok := m.running[id]
	if !ok {
		return
	}
	addr := ""
	if ri.inst.Settings != nil {
		addr = ri.inst.Settings.Address
	}
	if err := bringDown(ri.name, addr); err != nil {
		logger.Warning("awg: remove bring-down", ri.name, ":", err)
	}
	delete(m.running, id)
}

// CollectTraffic scrapes each running AWG interface via UAPI get=1 and returns
// per-client byte deltas since the previous scrape, plus emails whose last
// handshake is recent enough to count as online (or that transferred bytes
// this poll).
func (m *Manager) CollectTraffic() ([]Traffic, []string) {
	type snap struct {
		id    int
		name  string
		tag   string
		peers []PeerEntry
		last  map[string]clientCounters
	}
	m.mu.Lock()
	snaps := make([]snap, 0, len(m.running))
	for id, ri := range m.running {
		var peers []PeerEntry
		if ri.inst.Settings != nil {
			peers = ri.inst.Settings.EffectivePeers()
		}
		lastCopy := make(map[string]clientCounters, len(ri.last))
		maps.Copy(lastCopy, ri.last)
		snaps = append(snaps, snap{
			id:    id,
			name:  ri.name,
			tag:   ri.inst.Tag,
			peers: peers,
			last:  lastCopy,
		})
	}
	m.mu.Unlock()

	now := time.Now().Unix()
	var out []Traffic
	var online []string
	for _, s := range snaps {
		dumps, err := dumpPeers(s.name)
		if err != nil {
			logger.Warning("awg: dump peers", s.name, ":", err)
			continue
		}
		emailByHex := make(map[string]string, len(s.peers))
		for _, p := range s.peers {
			if !peerIsActive(p) || p.Email == "" {
				continue
			}
			if h := hexKey(p.PublicKey); h != "" {
				emailByHex[h] = p.Email
			}
		}

		newLast := make(map[string]clientCounters, len(dumps))
		for _, d := range dumps {
			email := emailByHex[d.PublicKeyHex]
			if email == "" {
				continue
			}
			// Server rx = bytes from client = Up; tx = bytes to client = Down.
			up, down := d.RxBytes, d.TxBytes
			newLast[email] = clientCounters{up: up, down: down}

			handshakeFresh := d.LastHandshakeSec > 0 && now-d.LastHandshakeSec <= onlineHandshakeWindow
			prev, had := s.last[email]
			du, dd := int64(0), int64(0)
			if had {
				du = up - prev.up
				dd = down - prev.down
				if du < 0 {
					du = 0
				}
				if dd < 0 {
					dd = 0
				}
			}
			if handshakeFresh || du > 0 || dd > 0 {
				online = append(online, email)
			}
			if had && (du > 0 || dd > 0) {
				out = append(out, Traffic{Tag: s.tag, Email: email, Up: du, Down: dd})
			}
		}

		m.mu.Lock()
		if cur, ok := m.running[s.id]; ok {
			cur.last = newLast
		}
		m.mu.Unlock()
	}
	return out, online
}

// InstanceFromInbound derives a desired Instance from an amneziawg inbound.
// Returns false when the inbound is not AWG or settings are unparseable.
func InstanceFromInbound(ib *model.Inbound) (Instance, bool) {
	if ib == nil || ib.Protocol != model.AmneziaWG {
		return Instance{}, false
	}
	var settings Settings
	if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
		return Instance{}, false
	}
	if settings.SecretKey == "" {
		return Instance{}, false
	}
	if settings.PublicKey == "" {
		if pub, err := wgutil.PublicKeyFromPrivate(settings.SecretKey); err == nil {
			settings.PublicKey = pub
		}
	}
	return Instance{
		ID:       ib.Id,
		Tag:      ib.Tag,
		Listen:   ib.Listen,
		Port:     ib.Port,
		Settings: &settings,
		NodeID:   ib.NodeID,
	}, true
}
