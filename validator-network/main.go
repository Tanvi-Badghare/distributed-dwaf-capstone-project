// main.go — Validator Node Server
// Starts the HTTP server and initialises the validator node.
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

	cfg := LoadConfig()

	log.Printf("[validator-%d] starting node", cfg.NodeID)
	log.Printf("[validator-%d] port=%d", cfg.NodeID, cfg.Port)
	log.Printf("[validator-%d] peers=%v", cfg.NodeID, cfg.Peers)
	log.Printf("[validator-%d] zkp-layer=%s", cfg.NodeID, cfg.ZKPLayerURL)

	node := NewValidatorNode(cfg)

	// ── Check ZKP Layer Connectivity ─────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := node.verifier.HealthCheck(ctx); err != nil {
		log.Printf("[validator-%d] warning: ZKP layer not reachable: %v",
			cfg.NodeID, err)
	} else {
		log.Printf("[validator-%d] ZKP layer reachable", cfg.NodeID)
	}

	// ── Gin Router Setup ─────────────────────────────────────────────────────
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// ── Health Endpoint ──────────────────────────────────────────────────────
	router.GET("/health", func(c *gin.Context) {

		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"node_id": cfg.NodeID,
			"version": "0.1.0",
		})
	})

	// ── Verification Endpoint ────────────────────────────────────────────────
	router.POST("/verify", func(c *gin.Context) {

		var req VerifyRequest

		if err := c.ShouldBindJSON(&req); err != nil {

			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})

			return
		}

		result, err := node.HandleVerify(c.Request.Context(), &req)

		if err != nil {

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})

			return
		}

		c.JSON(http.StatusOK, result)
	})

	// ── Vote Endpoint (peer validators) ──────────────────────────────────────
	router.POST("/vote", func(c *gin.Context) {

		var req VoteRequest

		if err := c.ShouldBindJSON(&req); err != nil {

			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})

			return
		}

		result, err := node.HandleVote(c.Request.Context(), &req)

		if err != nil {

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})

			return
		}

		c.JSON(http.StatusOK, result)
	})

	// ── Consensus Status Endpoint ───────────────────────────────────────────
	router.GET("/consensus/:request_id", func(c *gin.Context) {

		requestID := c.Param("request_id")

		status := node.GetConsensusStatus(requestID)

		c.JSON(http.StatusOK, status)
	})

	// ── Metrics Endpoint ─────────────────────────────────────────────────────
	router.GET("/metrics", func(c *gin.Context) {

		c.JSON(http.StatusOK, node.GetMetrics())
	})

	// ── HTTP Server ──────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: router,
	}

	// Start server in goroutine
	go func() {

		log.Printf("[validator-%d] server listening on :%d",
			cfg.NodeID, cfg.Port)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {

			log.Fatalf("[validator-%d] server error: %v",
				cfg.NodeID, err)
		}

	}()

	// ── Graceful Shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	log.Printf("[validator-%d] shutdown signal received", cfg.NodeID)

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {

		log.Printf("[validator-%d] shutdown error: %v",
			cfg.NodeID, err)

	} else {

		log.Printf("[validator-%d] shutdown complete",
			cfg.NodeID)
	}
}