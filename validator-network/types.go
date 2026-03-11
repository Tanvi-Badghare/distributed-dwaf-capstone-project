// types.go — shared request/response types and validator node state
package main

import (
	"sync"
	"time"
)

// ── Request / Response types ──────────────────────────────────────────────────

// VerifyRequest represents a verification request sent by the orchestrator
type VerifyRequest struct {
	RequestID      string    `json:"request_id"`
	ProofBytes     []byte    `json:"proof_bytes"`
	PublicInputs   [][]byte  `json:"public_inputs"`
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
	Timestamp      time.Time `json:"timestamp"`
}

// VerifyResponse represents a validator's response after verification
type VerifyResponse struct {
	RequestID   string  `json:"request_id"`
	NodeID      int     `json:"node_id"`
	Valid       bool    `json:"valid"`
	Consensus   bool    `json:"consensus"`
	VoteCount   int     `json:"vote_count"`
	TotalNodes  int     `json:"total_nodes"`
	ThreatScore float64 `json:"threat_score"`
	Latency     int64   `json:"latency_ms"`
}

// VoteRequest is sent between validator nodes during consensus
type VoteRequest struct {
	RequestID string `json:"request_id"`
	NodeID    int    `json:"node_id"`
	Valid     bool   `json:"valid"`
	Signature string `json:"signature"`
}

// VoteResponse confirms whether a vote was accepted
type VoteResponse struct {
	RequestID string `json:"request_id"`
	Accepted  bool   `json:"accepted"`
}

// ConsensusStatus tracks voting state for a specific request
type ConsensusStatus struct {
	RequestID   string       `json:"request_id"`
	Phase       string       `json:"phase"`
	Votes       map[int]bool `json:"votes"`
	VoteCount   int          `json:"vote_count"`
	Consensus   bool         `json:"consensus"`
	ConsensusAt *time.Time   `json:"consensus_at,omitempty"`
}

// NodeMetrics stores runtime metrics for monitoring validator performance
type NodeMetrics struct {
	NodeID           int     `json:"node_id"`
	TotalVerified    int64   `json:"total_verified"`
	TotalMalicious   int64   `json:"total_malicious"`
	TotalBenign      int64   `json:"total_benign"`
	ConsensusReached int64   `json:"consensus_reached"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	Uptime           string  `json:"uptime"`
}

// ── Validator Node ────────────────────────────────────────────────────────────

// ValidatorNode represents a validator instance in the network
type ValidatorNode struct {
	cfg       *Config
	verifier  *ZKPVerifier
	consensus *ConsensusEngine
	metrics   *Metrics
	startTime time.Time
}

// NewValidatorNode initializes a validator node
func NewValidatorNode(cfg *Config) *ValidatorNode {
	return &ValidatorNode{
		cfg:       cfg,
		verifier:  NewZKPVerifier(cfg.ZKPLayerURL),
		consensus: NewConsensusEngine(cfg),
		metrics:   NewMetrics(cfg.NodeID),
		startTime: time.Now(),
	}
}

// ── In-memory vote store ──────────────────────────────────────────────────────

// VoteStore safely stores consensus votes for each request
type VoteStore struct {
	mu    sync.RWMutex
	votes map[string]*ConsensusStatus
}

// NewVoteStore initializes the vote store
func NewVoteStore() *VoteStore {
	return &VoteStore{
		votes: make(map[string]*ConsensusStatus),
	}
}

// GetOrCreate returns the existing consensus status or creates a new one
func (vs *VoteStore) GetOrCreate(requestID string) *ConsensusStatus {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if _, ok := vs.votes[requestID]; !ok {
		vs.votes[requestID] = &ConsensusStatus{
			RequestID: requestID,
			Phase:     "pending",
			Votes:     make(map[int]bool),
		}
	}

	return vs.votes[requestID]
}

// Get retrieves consensus status safely
func (vs *VoteStore) Get(requestID string) *ConsensusStatus {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	if s, ok := vs.votes[requestID]; ok {
		return s
	}

	// return safe default if not found
	return &ConsensusStatus{
		RequestID: requestID,
		Phase:     "not_found",
		Votes:     make(map[int]bool),
	}
}