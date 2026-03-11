// config.go — loads validator node configuration from YAML or environment
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Validator Configuration ───────────────────────────────────────────────────

type Config struct {
	NodeID      int      `yaml:"node_id"`
	Port        int      `yaml:"port"`
	Peers       []string `yaml:"peers"`
	ZKPLayerURL string   `yaml:"zkp_layer_url"`
	Threshold   float64  `yaml:"threshold"`
}

// LoadConfig loads configuration from YAML file and environment variables
func LoadConfig() *Config {

	cfg := &Config{
		NodeID:      0,
		Port:        9000,
		Peers:       []string{},
		ZKPLayerURL: "http://localhost:8080",
		Threshold:   0.51,
	}

	// ── Load YAML Config ──
	configPath := os.Getenv("VALIDATOR_CONFIG")
	if configPath == "" {
		configPath = "config/validator-0.yaml"
	}

	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Printf("warning: could not parse config file %s: %v", configPath, err)
		} else {
			log.Printf("loaded config from %s", configPath)
		}
	} else {
		log.Printf("warning: config file not found (%s), using defaults", configPath)
	}

	// ── Environment Overrides ──

	if v := os.Getenv("NODE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			cfg.NodeID = id
		}
	}

	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Port = p
		}
	}

	if v := os.Getenv("PEERS"); v != "" {
		peers := strings.Split(v, ",")
		for i := range peers {
			peers[i] = strings.TrimSpace(peers[i])
		}
		cfg.Peers = peers
	}

	if v := os.Getenv("ZKP_LAYER_URL"); v != "" {
		cfg.ZKPLayerURL = strings.TrimSpace(v)
	}

	log.Printf(
		"config loaded → node_id=%d port=%d peers=%v zkp=%s threshold=%.2f",
		cfg.NodeID,
		cfg.Port,
		cfg.Peers,
		cfg.ZKPLayerURL,
		cfg.Threshold,
	)

	return cfg
}

// ── Metrics System ────────────────────────────────────────────────────────────

type Metrics struct {
	mu               sync.Mutex
	nodeID           int
	totalVerified    int64
	totalMalicious   int64
	totalBenign      int64
	consensusReached int64
	totalLatencyMs   float64
	startTime        time.Time
}

// NewMetrics initializes metrics collector
func NewMetrics(nodeID int) *Metrics {
	return &Metrics{
		nodeID:    nodeID,
		startTime: time.Now(),
	}
}

// Record updates metrics after each verification
func (m *Metrics) Record(valid bool, consensus bool, latency time.Duration) {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalVerified++

	if valid {
		m.totalMalicious++
	} else {
		m.totalBenign++
	}

	if consensus {
		m.consensusReached++
	}

	m.totalLatencyMs += float64(latency.Milliseconds())
}

// Snapshot returns metrics summary
func (m *Metrics) Snapshot() *NodeMetrics {

	m.mu.Lock()
	defer m.mu.Unlock()

	avg := 0.0
	if m.totalVerified > 0 {
		avg = m.totalLatencyMs / float64(m.totalVerified)
	}

	return &NodeMetrics{
		NodeID:           m.nodeID,
		TotalVerified:    m.totalVerified,
		TotalMalicious:   m.totalMalicious,
		TotalBenign:      m.totalBenign,
		ConsensusReached: m.consensusReached,
		AvgLatencyMs:     avg,
		Uptime:           fmt.Sprintf("%.0fs", time.Since(m.startTime).Seconds()),
	}
}