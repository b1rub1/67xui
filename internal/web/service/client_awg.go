package service

import (
	"encoding/json"
	"net/netip"

	"github.com/mhsanaei/3x-ui/v3/internal/awg"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

const defaultAWGBase = "10.66.0.0/24"

// prepareAWGClients validates and auto-fills the client list inside an AWG
// inbound's settings JSON before the inbound is persisted. This function is
// called from the generic inbound-save path exactly like
// prepareWireguardClients is for WireGuard.
func prepareAWGClients(inbound *model.Inbound) error {
	if inbound == nil || inbound.Protocol != model.AmneziaWG {
		return nil
	}
	var settings awg.Settings
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return common.NewError("awg: cannot parse settings:", err)
	}

	// Derive server public key from private key if not yet set.
	if settings.SecretKey != "" && settings.PublicKey == "" {
		pub, err := wgutil.PublicKeyFromPrivate(settings.SecretKey)
		if err != nil {
			return common.NewError("awg: derive server public key:", err)
		}
		settings.PublicKey = pub
	}

	// Auto-generate server keypair if none supplied.
	if settings.SecretKey == "" {
		priv, pub, err := wgutil.GenerateWireguardKeypair()
		if err != nil {
			return common.NewError("awg: generate server keypair:", err)
		}
		settings.SecretKey = priv
		settings.PublicKey = pub
	}

	// Auto-generate AWG 2.0 params if not present.
	if settings.Params.H1 == 0 {
		params, err := awg.GenerateParams()
		if err != nil {
			return common.NewError("awg: generate params:", err)
		}
		settings.Params = params
	}

	// Default tunnel address.
	if settings.Address == "" {
		settings.Address = "10.66.0.1/24"
	}

	// Collect already-used client IPs for allocation.
	used := make([]string, 0, len(settings.Clients)+len(settings.Peers))
	for _, p := range settings.EffectivePeers() {
		for _, ip := range p.AllowedIPs {
			used = append(used, ip)
		}
	}

	// Prefer the panel "clients" array; migrate legacy "peers" into it once.
	peers := settings.Clients
	if len(peers) == 0 && len(settings.Peers) > 0 {
		peers = settings.Peers
	}

	// Fill in missing keys and IPs for each peer.
	for i := range peers {
		peer := &peers[i]

		if peer.PrivateKey == "" && peer.PublicKey == "" {
			priv, pub, err := wgutil.GenerateWireguardKeypair()
			if err != nil {
				return common.NewError("awg: generate peer keypair:", err)
			}
			peer.PrivateKey = priv
			peer.PublicKey = pub
		} else if peer.PublicKey == "" && peer.PrivateKey != "" {
			pub, err := wgutil.PublicKeyFromPrivate(peer.PrivateKey)
			if err != nil {
				return common.NewError("awg: derive peer public key:", err)
			}
			peer.PublicKey = pub
		}

		if len(peer.AllowedIPs) == 0 {
			base := awgAllocationBase(used, defaultAWGBase)
			addr, err := allocateWireguardAddress(used, base)
			if err != nil {
				return common.NewError("awg: no free IP:", err)
			}
			peer.AllowedIPs = []string{addr}
		}
		used = append(used, peer.AllowedIPs...)
	}

	settings.Clients = peers
	settings.Peers = nil

	raw, err := json.Marshal(settings)
	if err != nil {
		return common.NewError("awg: marshal settings:", err)
	}
	inbound.Settings = string(raw)
	return nil
}

// awgAllocationBase returns the /24 base network derived from the already-used
// addresses, falling back to the supplied default.
func awgAllocationBase(used []string, fallback string) string {
	for _, u := range used {
		u = trimSpace(u)
		if p, err := netip.ParsePrefix(u); err == nil {
			if p.Addr().Is4() {
				if base, err := p.Addr().Prefix(24); err == nil {
					return base.String()
				}
			}
		}
	}
	return fallback
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
