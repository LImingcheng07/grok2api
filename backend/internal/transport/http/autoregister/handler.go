package autoregister

import (
	"context"
	"net/http"

	autoregisterapp "github.com/chenyme/grok2api/backend/internal/application/autoregister"
	"github.com/chenyme/grok2api/backend/internal/shared/response"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *autoregisterapp.Service
}

func NewHandler(service *autoregisterapp.Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(router *gin.RouterGroup) {
	router.GET("/auto-register/status", h.status)
	router.POST("/auto-register/run-once", h.runOnce)
	router.POST("/auto-register/stop", h.stop)
}

func (h *Handler) status(c *gin.Context) {
	if h.service == nil {
		response.Error(c, http.StatusServiceUnavailable, "autoRegisterUnavailable", "自动补号服务未启用")
		return
	}
	response.Success(c, http.StatusOK, h.service.Status())
}

func (h *Handler) runOnce(c *gin.Context) {
	if h.service == nil {
		response.Error(c, http.StatusServiceUnavailable, "autoRegisterUnavailable", "自动补号服务未启用")
		return
	}
	go h.service.TriggerOnce(context.WithoutCancel(c.Request.Context()))
	response.Success(c, http.StatusAccepted, h.service.Status())
}

func (h *Handler) stop(c *gin.Context) {
	if h.service == nil {
		response.Error(c, http.StatusServiceUnavailable, "autoRegisterUnavailable", "自动补号服务未启用")
		return
	}
	h.service.Stop()
	response.Success(c, http.StatusOK, h.service.Status())
}
