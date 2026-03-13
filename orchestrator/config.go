// config.go — loads orchestrator configuration
package main

import (
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadOrchestratorConfig() *OrchestratorConfig {

	cfg := &OrchestratorConfig{
		Port:           7000,
		MLDetectorURL:  "http://localhost:8000",
		ZKPLayerURL:    "http://localhost:8080",
		ValidatorURLs:  []string{"http://localhost:9000", "http://localhost:9001", "http://localhost:9002"},
		TAXIIServerURL: "http://localhost:6000",
		FeedbackURL:    "http://localhost:5000",
		BlockThreshold: 0.5,
	}

	configPath := os.Getenv("ORCHESTRATOR_CONFIG")
	if configPath == "" {
		configPath = "config/orchestrator-config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("warning: config file not found (%s), using defaults", configPath)
	} else {

		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Printf("warning: could not parse config %s: %v", configPath, err)
		} else {
			log.Printf("loaded orchestrator config from %s", configPath)
		}
	}

	// ── Environment overrides ───────────────────────────────────────────────

	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Port = p
		}
	}

	if v := os.Getenv("ML_DETECTOR_URL"); v != "" {
		cfg.MLDetectorURL = strings.TrimSpace(v)
	}

	if v := os.Getenv("ZKP_LAYER_URL"); v != "" {
		cfg.ZKPLayerURL = strings.TrimSpace(v)
	}

	if v := os.Getenv("VALIDATOR_URLS"); v != "" {

		raw := strings.Split(v, ",")

		var cleaned []string
		for _, u := range raw {
			cleaned = append(cleaned, strings.TrimSpace(u))
		}

		cfg.ValidatorURLs = cleaned
	}

	if v := os.Getenv("TAXII_SERVER_URL"); v != "" {
		cfg.TAXIIServerURL = strings.TrimSpace(v)
	}

	if v := os.Getenv("FEEDBACK_URL"); v != "" {
		cfg.FeedbackURL = strings.TrimSpace(v)
	}

	if v := os.Getenv("BLOCK_THRESHOLD"); v != "" {
		if t, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.BlockThreshold = t
		}
	}

	// ── Startup config summary ──────────────────────────────────────────────

	log.Printf(
		"orchestrator config: port=%d ml=%s zkp=%s validators=%v taxii=%s feedback=%s threshold=%.2f",
		cfg.Port,
		cfg.MLDetectorURL,
		cfg.ZKPLayerURL,
		cfg.ValidatorURLs,
		cfg.TAXIIServerURL,
		cfg.FeedbackURL,
		cfg.BlockThreshold,
	)

	return cfg
}