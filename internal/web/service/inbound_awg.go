package service

import (
	"context"
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/awg"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// DesiredAWGInstances derives the set of AWG interfaces this node should be
// running: one per enabled local AWG inbound. The peer list for each instance
// is the full enabled-client set so Reconcile can apply it atomically.
func (s *InboundService) DesiredAWGInstances() ([]awg.Instance, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol = ? AND enable = ? AND node_id IS NULL", model.AmneziaWG, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}

	instances := make([]awg.Instance, 0, len(inbounds))
	for _, ib := range inbounds {
		inst, ok := awgInstanceFromInbound(ib)
		if !ok {
			continue
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

// awgInstanceFromInbound parses an AWG inbound row into an awg.Instance.
// Returns false when settings are unparseable so the caller can skip quietly.
func awgInstanceFromInbound(ib *model.Inbound) (awg.Instance, bool) {
	var settings awg.Settings
	if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
		logger.Warning("awg: parse settings for inbound", ib.Id, ":", err)
		return awg.Instance{}, false
	}
	return awg.Instance{
		ID:       ib.Id,
		Tag:      ib.Tag,
		Listen:   ib.Listen,
		Port:     ib.Port,
		Settings: &settings,
	}, true
}

// applyLocalAWG hot-syncs the peer list of one local AWG inbound immediately
// after a client edit commits, without waiting for the reconcile cron job.
func (s *InboundService) applyLocalAWG(ctx context.Context, inboundID int) {
	db := database.GetDB()
	var ib model.Inbound
	if err := db.First(&ib, inboundID).Error; err != nil {
		logger.Warning("awg: load inbound for hot-apply:", err)
		return
	}
	if ib.Protocol != model.AmneziaWG || !ib.Enable || ib.NodeID != nil {
		return
	}
	var settings awg.Settings
	if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
		logger.Warning("awg: parse settings for hot-apply:", err)
		return
	}
	if err := awg.GetManager().ApplyPeers(inboundID, settings.EffectivePeers()); err != nil {
		logger.Warning("awg: hot-apply peers for inbound", inboundID, ":", err)
	}
}
