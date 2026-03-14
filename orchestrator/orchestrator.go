// orchestrator.go — core pipeline: ML → ZKP → Validator → TAXII
package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

type Orchestrator struct {
	cfg       *OrchestratorConfig
	ml        *MLClient
	zkp       *ZKPCoordinator
	validator *ValidatorClient
	taxii     *TAXIIPublisher
	feedback  *FeedbackLoop
	store     *StatusStore
	metrics   *MetricsTracker
}

func NewOrchestrator(cfg *OrchestratorConfig) *Orchestrator {
	return &Orchestrator{
		cfg:       cfg,
		ml:        NewMLClient(cfg.MLDetectorURL),
		zkp:       NewZKPCoordinator(cfg.ZKPLayerURL),
		validator: NewValidatorClient(cfg.ValidatorURLs),
		taxii:     NewTAXIIPublisher(cfg.TAXIIServerURL),
		feedback:  NewFeedbackLoop(cfg.FeedbackURL),
		store:     NewStatusStore(),
		metrics:   NewMetricsTracker(),
	}
}

// Inspect runs the full pipeline for a single HTTP request.
//
//	Stage I  → ML Detector   (classify + extract features)
//	Stage II → ZKP Layer     (generate Groth16 proof)
//	Stage III→ Validator Net (verify proof + consensus)
//	Stage IV → TAXII Server  (publish if malicious + consensus)
func (o *Orchestrator) Inspect(ctx context.Context, req *InspectRequest) (*InspectResult, error) {
	start := time.Now()

	if req.RequestID == "" {
		req.RequestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	o.store.Set(req.RequestID, "ml_detection", nil)
	log.Printf("[orchestrator] inspecting %s %s (id=%s)", req.Method, req.URL, req.RequestID)

	result := &InspectResult{
		RequestID: req.RequestID,
		Verdict:   "allow",
	}

	// ── Stage I: ML Detection ─────────────────────────────────────────────────
	mlStart := time.Now()
	mlResp, err := o.ml.Detect(ctx, req)
	if err != nil {
		log.Printf("[orchestrator] ML detection failed for %s: %v", req.RequestID, err)
		return nil, fmt.Errorf("ml detection failed: %w", err)
	}
	result.Stages.MLLatencyMs = time.Since(mlStart).Milliseconds()
	result.Classification = mlResp.Classification
	result.ThreatScore = mlResp.ThreatScore

	log.Printf("[orchestrator] ML: %s score=%.3f (%dms)",
		mlResp.Classification, mlResp.ThreatScore, result.Stages.MLLatencyMs)

	// Fast-path: allow benign traffic immediately
	if mlResp.Classification == "benign" && mlResp.ThreatScore < o.cfg.BlockThreshold {
		result.Verdict = "allow"
		result.TotalLatencyMs = time.Since(start).Milliseconds()
		o.store.Set(req.RequestID, "complete", result)
		o.metrics.Record(false, false, result.TotalLatencyMs)
		return result, nil
	}

	o.store.Set(req.RequestID, "zkp_generation", nil)

	// ── Stage II: ZKP Proof Generation ───────────────────────────────────────
	zkpStart := time.Now()
	proof, err := o.zkp.GenerateProof(ctx, mlResp.Features, mlResp.Classification, mlResp.ThreatScore)
	if err != nil {
		log.Printf("[orchestrator] ZKP generation failed for %s: %v", req.RequestID, err)
		// ZKP failure: block anyway if ML says malicious
		result.Verdict = "block"
		result.ProofValid = false
		result.TotalLatencyMs = time.Since(start).Milliseconds()
		o.store.Set(req.RequestID, "complete", result)
		o.metrics.Record(true, false, result.TotalLatencyMs)
		return result, nil
	}
	result.Stages.ZKPLatencyMs = time.Since(zkpStart).Milliseconds()

	log.Printf("[orchestrator] ZKP proof generated (%dms)", result.Stages.ZKPLatencyMs)
	o.store.Set(req.RequestID, "validator_consensus", nil)

	// ── Stage III: Validator Consensus ────────────────────────────────────────
	valStart := time.Now()
	valResp, err := o.validator.Submit(ctx, req.RequestID, proof,
		mlResp.Classification, mlResp.ThreatScore)
	if err != nil {
		log.Printf("[orchestrator] validator failed for %s: %v", req.RequestID, err)
		result.ProofValid = false
		result.Consensus = false
	} else {
		result.ProofValid = valResp.Valid
		result.Consensus = valResp.Consensus
	}
	result.Stages.ValidatorLatencyMs = time.Since(valStart).Milliseconds()

	log.Printf("[orchestrator] validator: valid=%v consensus=%v (%dms)",
		result.ProofValid, result.Consensus, result.Stages.ValidatorLatencyMs)

	// ── Verdict ───────────────────────────────────────────────────────────────
	if mlResp.Classification == "malicious" && result.ProofValid {
		result.Verdict = "block"
	} else {
		result.Verdict = "allow"
	}

	// ── Stage IV: TAXII Publishing (only for confirmed threats) ───────────────
	if result.Verdict == "block" && result.Consensus {
		o.store.Set(req.RequestID, "taxii_publish", nil)
		taxiiStart := time.Now()
		taxiiResp, err := o.taxii.Publish(ctx, req, result)
		result.Stages.TAXIILatencyMs = time.Since(taxiiStart).Milliseconds()
		if err == nil && taxiiResp.Published {
			result.STIXPublished = true
			log.Printf("[orchestrator] TAXII published bundle %s (%dms)",
				taxiiResp.BundleID, result.Stages.TAXIILatencyMs)
		}
	}

	// ── Stage V: Feedback ─────────────────────────────────────────────────────
	if result.Verdict == "block" {
		o.feedback.Record(ThreatEvent{
			RequestID:      req.RequestID,
			Classification: mlResp.Classification,
			ThreatScore:    mlResp.ThreatScore,
			Features:       mlResp.Features,
			Consensus:      result.Consensus,
			Timestamp:      time.Now(),
		})
	}

	result.TotalLatencyMs = time.Since(start).Milliseconds()
	o.store.Set(req.RequestID, "complete", result)
	o.metrics.Record(result.Verdict == "block", result.STIXPublished, result.TotalLatencyMs)

	log.Printf("[orchestrator] %s → %s (total=%dms)",
		req.RequestID, result.Verdict, result.TotalLatencyMs)

	return result, nil
}

func (o *Orchestrator) GetStatus(requestID string) *PipelineStatus {
	return o.store.Get(requestID)
}

func (o *Orchestrator) GetMetrics() *OrchestratorMetrics {
	return o.metrics.Snapshot()
}