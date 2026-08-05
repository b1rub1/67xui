package awg

import (
	"fmt"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
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
	inst Instance
	name string // kernel interface name
}

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
			if err := bringDown(ri.name); err != nil {
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
			m.running[inst.ID] = &runningIface{inst: inst, name: name}
		} else {
			// Already running — hot-sync peers without restarting.
			if err := syncPeers(ri.name, inst.Settings.EffectivePeers()); err != nil {
				logger.Warning("awg: sync-peers", ri.name, ":", err)
			}
			ri.inst = inst
		}
	}
	return nil
}

// StopAll tears down every managed interface. Called during panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ri := range m.running {
		if err := bringDown(ri.name); err != nil {
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
	ri, ok := m.running[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("awg: inbound %d is not running", id)
	}
	return syncPeers(ri.name, peers)
}
