// main.go — Orchestrator HTTP Proxy Server
// Central coordinator: receives HTTP requests, routes through
// ML → ZKP → Validator → TAXII pipeline.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := LoadOrchestratorConfig()

	log.Printf("[orchestrator] starting on port %d", cfg.Port)
	log.Printf("[orchestrator] ml-detector:      %s", cfg.MLDetectorURL)
	log.Printf("[orchestrator] zkp-layer:         %s", cfg.ZKPLayerURL)
	log.Printf("[orchestrator] validators:         %v", cfg.ValidatorURLs)
	log.Printf("[orchestrator] taxii-server:       %s", cfg.TAXIIServerURL)

	orch := NewOrchestrator(cfg)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// ── Health ────────────────────────────────────────────────────────────────
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "orchestrator",
			"version": "0.1.0",
		})
	})

	// ── Main pipeline endpoint ────────────────────────────────────────────────
	// Accepts a raw HTTP request, runs full ML→ZKP→Validator pipeline
	router.POST("/inspect", func(c *gin.Context) {
		var req InspectRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result, err := orch.Inspect(c.Request.Context(), &req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, result)
	})

	// ── Pipeline status ───────────────────────────────────────────────────────
	router.GET("/status/:request_id", func(c *gin.Context) {
		status := orch.GetStatus(c.Param("request_id"))
		c.JSON(http.StatusOK, status)
	})

	// ── Metrics ───────────────────────────────────────────────────────────────
	router.GET("/metrics", func(c *gin.Context) {
		c.JSON(http.StatusOK, orch.GetMetrics())
	})

	// ── Feedback trigger (Stage V) ────────────────────────────────────────────
	router.POST("/feedback/retrain", func(c *gin.Context) {
		err := orch.feedback.TriggerRetrain(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "retrain triggered"})
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: router,
	}

	go func() {
		log.Printf("[orchestrator] listening on :%d", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[orchestrator] server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("[orchestrator] shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}