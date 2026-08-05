package job

import (
	"github.com/mhsanaei/3x-ui/v3/internal/awg"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// AWGJob reconciles the running AmneziaWG interfaces against the enabled AWG
// inbounds in the database, and folds per-client traffic / online status
// scraped from each interface's UAPI dump into the usual accounting paths.
type AWGJob struct {
	inboundService service.InboundService
}

// NewAWGJob creates a new AWG reconcile/traffic job instance.
func NewAWGJob() *AWGJob {
	return new(AWGJob)
}

// Run reconciles desired AWG inbounds with running interfaces and records
// per-client traffic deltas and online status.
func (j *AWGJob) Run() {
	desired, err := j.inboundService.DesiredAWGInstances()
	if err != nil {
		logger.Warning("awg job: get desired instances failed:", err)
		return
	}

	activeTags := make([]string, 0, len(desired))
	for _, inst := range desired {
		activeTags = append(activeTags, inst.Tag)
	}

	if err := awg.GetManager().Reconcile(desired); err != nil {
		logger.Warning("awg job: reconcile failed:", err)
	}

	deltas, onlineEmails := awg.GetManager().CollectTraffic()

	clientTraffics := make([]*xray.ClientTraffic, 0, len(deltas))
	inboundUp := make(map[string]int64)
	inboundDown := make(map[string]int64)
	for _, d := range deltas {
		clientTraffics = append(clientTraffics, &xray.ClientTraffic{
			Email: d.Email,
			Up:    d.Up,
			Down:  d.Down,
		})
		inboundUp[d.Tag] += d.Up
		inboundDown[d.Tag] += d.Down
	}

	traffics := make([]*xray.Traffic, 0, len(inboundUp))
	for tag, up := range inboundUp {
		traffics = append(traffics, &xray.Traffic{
			IsInbound: true,
			Tag:       tag,
			Up:        up,
			Down:      inboundDown[tag],
		})
	}

	if len(traffics) > 0 || len(clientTraffics) > 0 {
		if _, _, err := j.inboundService.AddTraffic(traffics, clientTraffics); err != nil {
			logger.Warning("awg job: add traffic failed:", err)
		}
	}

	j.inboundService.RefreshLocalOnlineClients(onlineEmails, activeTags)
}
