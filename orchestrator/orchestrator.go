// orchestrator.go — core pipeline coordinator
package main

import (
	"context"
	"fmt"
	"time"
)

type Orchestrator struct {
	cfg        *OrchestratorConfig
	ml         *MLClient
	zkp        *ZKPCoordinator
	validators *ValidatorClient
	taxii      *TAXIIPublisher
	feedback   *FeedbackLoop

	status  *StatusStore
	metrics *MetricsTracker
}

func NewOrchestrator(cfg *OrchestratorConfig) *Orchestrator {

	return &Orchestrator{
		cfg:        cfg,
		ml:         NewMLClient(cfg.MLDetectorURL),
		zkp:        NewZKPCoordinator(cfg.ZKPLayerURL),
		validators: NewValidatorClient(cfg.ValidatorURLs),
		taxii:      NewTAXIIPublisher(cfg.TAXIIServerURL),
		feedback:   NewFeedbackLoop(cfg.FeedbackURL),

		status:  NewStatusStore(),
		metrics: NewMetricsTracker(),
	}
}

func (o *Orchestrator) Inspect(ctx context.Context, req *InspectRequest) (*InspectResult, error) {

	start := time.Now()

	o.status.Set(req.RequestID, PhaseReceived, nil)

	// ── Stage I: ML Detection ─────────────────────────────────

	o.status.Set(req.RequestID, PhaseML, nil)

	mlResp, err := o.ml.Detect(ctx, req)
	if err != nil {
		o.status.Set(req.RequestID, PhaseFailed, nil)
		return nil, fmt.Errorf("ml stage failed: %w", err)
	}

	// ── Stage II: ZKP Proof Generation ────────────────────────

	o.status.Set(req.RequestID, PhaseZKP, nil)

	proof, err := o.zkp.GenerateProof(
		ctx,
		mlResp.Features,
		mlResp.Classification,
		mlResp.ThreatScore,
	)

	if err != nil {
		o.status.Set(req.RequestID, PhaseFailed, nil)
		return nil, fmt.Errorf("zkp stage failed: %w", err)
	}

	// ── Stage III: Validator Consensus ────────────────────────

	o.status.Set(req.RequestID, PhaseValidators, nil)

	valResp, err := o.validators.Submit(
		ctx,
		req.RequestID,
		proof,
		mlResp.Classification,
		mlResp.ThreatScore,
	)

	if err != nil {
		o.status.Set(req.RequestID, PhaseFailed, nil)
		return nil, fmt.Errorf("validator stage failed: %w", err)
	}

	// ── Result assembly ───────────────────────────────────────

	result := &InspectResult{
		RequestID:      req.RequestID,
		Classification: mlResp.Classification,
		ThreatScore:    mlResp.ThreatScore,
		Consensus:      valResp.Consensus,
		ProofValid:     valResp.Valid,
	}

	if mlResp.ThreatScore >= o.cfg.BlockThreshold {
		result.Verdict = "block"
	} else {
		result.Verdict = "allow"
	}

	// ── Stage IV: TAXII Publishing ────────────────────────────

	if result.Classification == "malicious" &&
		result.Consensus &&
		result.ProofValid {

		o.status.Set(req.RequestID, PhaseTAXII, result)

		taxiiResp, _ := o.taxii.Publish(ctx, req, result)

		if taxiiResp != nil {
			result.STIXPublished = taxiiResp.Published
		}

		// ── Stage V: Feedback Loop ─────────────────────────────

		o.feedback.Record(ThreatEvent{
			RequestID:      req.RequestID,
			Classification: result.Classification,
			ThreatScore:    result.ThreatScore,
			Features:       mlResp.Features,
			Consensus:      result.Consensus,
			Timestamp:      time.Now(),
		})
	}

	// ── Finalize ──────────────────────────────────────────────

	result.TotalLatencyMs = time.Since(start).Milliseconds()

	o.metrics.Record(
		result.Verdict == "block",
		result.STIXPublished,
		result.TotalLatencyMs,
	)

	o.status.Set(req.RequestID, PhaseCompleted, result)

	return result, nil
}

func (o *Orchestrator) GetStatus(id string) *PipelineStatus {
	return o.status.Get(id)
}

func (o *Orchestrator) GetMetrics() *OrchestratorMetrics {
	return o.metrics.Snapshot()
}