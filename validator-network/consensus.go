// consensus.go — majority approval logic for the validator network
package main

import (
	"log"
	"sync"
	"time"
)

// ConsensusEngine manages validator voting and determines when consensus is reached
type ConsensusEngine struct {
	cfg     *Config
	store   *VoteStore
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

// NewConsensusEngine initializes consensus tracking
func NewConsensusEngine(cfg *Config) *ConsensusEngine {

	return &ConsensusEngine{
		cfg:     cfg,
		store:   NewVoteStore(),
		waiters: make(map[string][]chan struct{}),
	}
}

// CastVote records a vote from a validator node
func (ce *ConsensusEngine) CastVote(requestID string, nodeID int, valid bool) {

	status := ce.store.GetOrCreate(requestID)

	ce.store.mu.Lock()

	status.Votes[nodeID] = valid
	status.VoteCount = len(status.Votes)

	totalNodes := len(ce.cfg.Peers) + 1

	reached, approved := ce.evaluateConsensus(status, totalNodes)

	if reached && !status.Consensus {

		status.Consensus = true
		now := time.Now()
		status.ConsensusAt = &now
		status.Phase = "consensus"

		if approved {
			log.Printf("[consensus] APPROVED %s — %d/%d votes",
				requestID, status.VoteCount, totalNodes)
		} else {
			log.Printf("[consensus] REJECTED %s — %d/%d votes",
				requestID, status.VoteCount, totalNodes)
		}
	}

	ce.store.mu.Unlock()

	if reached {
		ce.notifyWaiters(requestID)
	}
}

// evaluateConsensus determines if majority threshold has been reached
func (ce *ConsensusEngine) evaluateConsensus(
	status *ConsensusStatus,
	totalNodes int,
) (reached bool, approved bool) {

	threshold := totalNodes/2 + 1

	approveCount := 0
	rejectCount := 0

	for _, v := range status.Votes {
		if v {
			approveCount++
		} else {
			rejectCount++
		}
	}

	if approveCount >= threshold {
		return true, true
	}

	if rejectCount >= threshold {
		return true, false
	}

	return false, false
}

// WaitForConsensus blocks until consensus or timeout
func (ce *ConsensusEngine) WaitForConsensus(
	requestID string,
	timeout time.Duration,
) (bool, int) {

	status := ce.store.Get(requestID)

	if status.Consensus {
		return true, status.VoteCount
	}

	ch := make(chan struct{}, 1)

	ce.mu.Lock()
	ce.waiters[requestID] = append(ce.waiters[requestID], ch)
	ce.mu.Unlock()

	select {

	case <-ch:
		status = ce.store.Get(requestID)
		return status.Consensus, status.VoteCount

	case <-time.After(timeout):
		status = ce.store.Get(requestID)
		return status.Consensus, status.VoteCount
	}
}

// notifyWaiters wakes all waiting goroutines
func (ce *ConsensusEngine) notifyWaiters(requestID string) {

	ce.mu.Lock()
	waiters := ce.waiters[requestID]
	delete(ce.waiters, requestID)
	ce.mu.Unlock()

	for _, ch := range waiters {

		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// GetStatus returns consensus status
func (ce *ConsensusEngine) GetStatus(requestID string) *ConsensusStatus {
	return ce.store.Get(requestID)
}