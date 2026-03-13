// types.go — shared types for the orchestrator
package main

import (
	"sync"
	"time"
)

//
// ── Pipeline Phase Constants ─────────────────────────────────────────────────
//

const (
	PhaseReceived   = "received"
	PhaseML         = "ml_analysis"
	PhaseZKP        = "zkp_generation"
	PhaseValidators = "validator_consensus"
	PhaseTAXII      = "taxii_publish"
	PhaseCompleted  = "completed"
	PhaseFailed     = "failed"
)

//
// ── Inbound request ───────────────────────────────────────────────────────────
//

type InspectRequest struct {
	RequestID   string `json:"request_id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	ContentType string `json:"content_type"`
	Cookie      string `json:"cookie"`
	Length      int    `json:"length"`
	Content     string `json:"content"`
	Host        string `json:"host"`
	SourceApp   string `json:"source_app"` // federated app sending traffic
}

//
// ── Pipeline result ───────────────────────────────────────────────────────────
//

type InspectResult struct {
	RequestID      string         `json:"request_id"`
	Verdict        string         `json:"verdict"` // "block" | "allow"
	Classification string         `json:"classification"`
	ThreatScore    float64        `json:"threat_score"`
	Consensus      bool           `json:"consensus"`
	ProofValid     bool           `json:"proof_valid"`
	STIXPublished  bool           `json:"stix_published"`
	Error          string         `json:"error,omitempty"`
	Stages         PipelineStages `json:"stages"`
	TotalLatencyMs int64          `json:"total_latency_ms"`
}

type PipelineStages struct {
	MLLatencyMs        int64 `json:"ml_latency_ms"`
	ZKPLatencyMs       int64 `json:"zkp_latency_ms"`
	ValidatorLatencyMs int64 `json:"validator_latency_ms"`
	TAXIILatencyMs     int64 `json:"taxii_latency_ms"`
}

//
// ── Pipeline status tracker ───────────────────────────────────────────────────
//

type PipelineStatus struct {
	RequestID string         `json:"request_id"`
	Phase     string         `json:"phase"`
	Result    *InspectResult `json:"result,omitempty"`
}

//
// ── Orchestrator metrics ──────────────────────────────────────────────────────
//

type OrchestratorMetrics struct {
	TotalRequests int64   `json:"total_requests"`
	TotalBlocked  int64   `json:"total_blocked"`
	TotalAllowed  int64   `json:"total_allowed"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	STIXPublished int64   `json:"stix_published"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

//
// ── Status store ──────────────────────────────────────────────────────────────
//

type StatusStore struct {
	mu      sync.RWMutex
	entries map[string]*PipelineStatus
}

func NewStatusStore() *StatusStore {
	return &StatusStore{
		entries: make(map[string]*PipelineStatus),
	}
}

func (s *StatusStore) Set(id string, phase string, result *InspectResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[id] = &PipelineStatus{
		RequestID: id,
		Phase:     phase,
		Result:    result,
	}
}

func (s *StatusStore) Get(id string) *PipelineStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e, ok := s.entries[id]; ok {
		return e
	}

	return &PipelineStatus{
		RequestID: id,
		Phase:     "not_found",
	}
}

//
// ── Config ────────────────────────────────────────────────────────────────────
//

type OrchestratorConfig struct {
	Port           int      `yaml:"port"`
	MLDetectorURL  string   `yaml:"ml_detector_url"`
	ZKPLayerURL    string   `yaml:"zkp_layer_url"`
	ValidatorURLs  []string `yaml:"validator_urls"`
	TAXIIServerURL string   `yaml:"taxii_server_url"`
	FeedbackURL    string   `yaml:"feedback_url"`
	BlockThreshold float64  `yaml:"block_threshold"`
}

//
// ── Metrics tracker ───────────────────────────────────────────────────────────
//

type MetricsTracker struct {
	mu            sync.Mutex
	total         int64
	blocked       int64
	allowed       int64
	stixPublished int64
	totalLatency  float64
	startTime     time.Time
}

func NewMetricsTracker() *MetricsTracker {
	return &MetricsTracker{
		startTime: time.Now(),
	}
}

func (m *MetricsTracker) Record(blocked bool, stix bool, latency int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.total++

	if blocked {
		m.blocked++
	} else {
		m.allowed++
	}

	if stix {
		m.stixPublished++
	}

	m.totalLatency += float64(latency)
}

func (m *MetricsTracker) Snapshot() *OrchestratorMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	avg := 0.0
	if m.total > 0 {
		avg = m.totalLatency / float64(m.total)
	}

	uptime := int64(time.Since(m.startTime).Seconds())

	return &OrchestratorMetrics{
		TotalRequests: m.total,
		TotalBlocked:  m.blocked,
		TotalAllowed:  m.allowed,
		AvgLatencyMs:  avg,
		STIXPublished: m.stixPublished,
		UptimeSeconds: uptime,
	}
}