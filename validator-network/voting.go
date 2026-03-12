// voting.go — threshold voting logic for the validator network
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// HandleVerify processes a new proof verification request
func (n *ValidatorNode) HandleVerify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {

	start := time.Now()

	// 1. Verify proof via ZKP layer
	valid, err := n.verifier.VerifyProof(ctx, req.ProofBytes, req.PublicInputs)
	if err != nil {
		log.Printf("[validator-%d] ZKP verification error for %s: %v",
			n.cfg.NodeID, req.RequestID, err)
		valid = false
	}

	log.Printf("[validator-%d] proof %s → valid=%v (%.2fms)",
		n.cfg.NodeID,
		req.RequestID,
		valid,
		float64(time.Since(start).Microseconds())/1000,
	)

	// 2. Record own vote
	n.consensus.CastVote(req.RequestID, n.cfg.NodeID, valid)

	// 3. Broadcast vote to peers
	n.broadcastVote(ctx, req.RequestID, valid)

	// 4. Wait for consensus
	consensus, voteCount := n.consensus.WaitForConsensus(req.RequestID, 2*time.Second)

	n.metrics.Record(valid, consensus, time.Since(start))

	return &VerifyResponse{
		RequestID:   req.RequestID,
		NodeID:      n.cfg.NodeID,
		Valid:       valid,
		Consensus:   consensus,
		VoteCount:   voteCount,
		TotalNodes:  len(n.cfg.Peers) + 1,
		ThreatScore: req.ThreatScore,
		Latency:     time.Since(start).Milliseconds(),
	}, nil
}

// HandleVote processes vote messages from peer validators
func (n *ValidatorNode) HandleVote(ctx context.Context, req *VoteRequest) (*VoteResponse, error) {

	log.Printf("[validator-%d] received vote from node-%d for %s → valid=%v",
		n.cfg.NodeID, req.NodeID, req.RequestID, req.Valid)

	n.consensus.CastVote(req.RequestID, req.NodeID, req.Valid)

	return &VoteResponse{
		RequestID: req.RequestID,
		Accepted:  true,
	}, nil
}

// broadcastVote sends the validator's vote to all peers concurrently
func (n *ValidatorNode) broadcastVote(ctx context.Context, requestID string, valid bool) {

	if len(n.cfg.Peers) == 0 {
		return
	}

	vote := VoteRequest{
		RequestID: requestID,
		NodeID:    n.cfg.NodeID,
		Valid:     valid,
	}

	body, err := json.Marshal(vote)
	if err != nil {
		log.Printf("[validator-%d] failed to serialize vote: %v",
			n.cfg.NodeID, err)
		return
	}

	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	for _, peer := range n.cfg.Peers {

		wg.Add(1)

		go func(peerAddr string) {

			defer wg.Done()

			peerURL := fmt.Sprintf("http://%s/vote", peerAddr)

			peerCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(
				peerCtx,
				http.MethodPost,
				peerURL,
				bytes.NewReader(body),
			)
			if err != nil {
				log.Printf("[validator-%d] request creation failed for %s: %v",
					n.cfg.NodeID, peerURL, err)
				return
			}

			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[validator-%d] vote broadcast to %s failed: %v",
					n.cfg.NodeID, peerURL, err)
				return
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("[validator-%d] peer %s returned status %d",
					n.cfg.NodeID, peerURL, resp.StatusCode)
			}

		}(peer)
	}

	wg.Wait()
}

// GetConsensusStatus returns the current voting status
func (n *ValidatorNode) GetConsensusStatus(requestID string) *ConsensusStatus {
	return n.consensus.GetStatus(requestID)
}

// GetMetrics returns node runtime metrics
func (n *ValidatorNode) GetMetrics() *NodeMetrics {
	return n.metrics.Snapshot()
}