package job

import (
	"github.com/mhsanaei/3x-ui/v3/internal/awg"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// AWGJob reconciles the running AmneziaWG interfaces against the enabled AWG
// inbounds in the database. It brings up new interfaces, tears down removed
// ones, and hot-syncs peer lists on changes — all without restarting the panel
// or touching the Xray process.
type AWGJob struct {
	inboundService service.InboundService
}

// NewAWGJob creates a new AWG reconcile job instance.
func NewAWGJob() *AWGJob {
	return new(AWGJob)
}

// Run reconciles desired AWG inbounds with running interfaces.
func (j *AWGJob) Run() {
	desired, err := j.inboundService.DesiredAWGInstances()
	if err != nil {
		logger.Warning("awg job: get desired instances failed:", err)
		return
	}
	if err := awg.GetManager().Reconcile(desired); err != nil {
		logger.Warning("awg job: reconcile failed:", err)
	}
}
