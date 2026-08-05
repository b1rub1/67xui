package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/awg"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

// AWGController exposes helper endpoints consumed by the AWG inbound form.
// These are utility routes only — inbound CRUD still goes through the standard
// InboundController.
type AWGController struct{}

func NewAWGController(g *gin.RouterGroup) *AWGController {
	a := &AWGController{}
	g.POST("/keypair", a.GenKeypair)
	g.POST("/params", a.GenParams)
	return a
}

// GenKeypair generates a fresh Curve25519 keypair for an AWG server or client.
//
//	POST /panel/api/awg/keypair
//	Response: { "privateKey": "...", "publicKey": "..." }
func (a *AWGController) GenKeypair(c *gin.Context) {
	priv, pub, err := wgutil.GenerateWireguardKeypair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"privateKey": priv,
		"publicKey":  pub,
	})
}

// GenParams generates a fresh set of AWG 2.0 obfuscation parameters.
//
//	POST /panel/api/awg/params
//	Response: { "success": true, "params": { "jc":..., "jmin":..., ... } }
func (a *AWGController) GenParams(c *gin.Context) {
	params, err := awg.GenerateParams()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"params":  params,
	})
}
