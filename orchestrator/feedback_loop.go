// feedback_loop.go — Stage V: triggers model retraining and WAF rule updates
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FeedbackLoop struct {
	feedbackURL string
	httpClient  *http.Client

	mu         sync.Mutex
	buffer     []ThreatEvent
	flushEvery int
	flushing   bool
}

type ThreatEvent struct {
	RequestID      string    `json:"request_id"`
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
	Features       []float64 `json:"features"`
	Consensus      bool      `json:"consensus"`
	Timestamp      time.Time `json:"timestamp"`
}

func NewFeedbackLoop(feedbackURL string) *FeedbackLoop {
	return &FeedbackLoop{
		feedbackURL: strings.TrimRight(strings.TrimSpace(feedbackURL), "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		buffer:     make([]ThreatEvent, 0, 100),
		flushEvery: 50, // flush after 50 malicious events
	}
}

// Record buffers a threat event for feedback.
// Automatically flushes when buffer reaches threshold.
func (f *FeedbackLoop) Record(event ThreatEvent) {

	f.mu.Lock()

	// prevent unlimited growth
	if len(f.buffer) < 1000 {
		f.buffer = append(f.buffer, event)
	}

	shouldFlush := len(f.buffer) >= f.flushEvery && !f.flushing

	if shouldFlush {
		f.flushing = true
	}

	f.mu.Unlock()

	if shouldFlush {
		go f.flush()
	}
}

// TriggerRetrain manually triggers model retraining via feedback service.
func (f *FeedbackLoop) TriggerRetrain(ctx context.Context) error {

	f.mu.Lock()
	events := make([]ThreatEvent, len(f.buffer))
	copy(events, f.buffer)

	f.buffer = f.buffer[:0]
	f.mu.Unlock()

	return f.sendToFeedbackService(ctx, events)
}

func (f *FeedbackLoop) flush() {

	f.mu.Lock()

	events := make([]ThreatEvent, len(f.buffer))
	copy(events, f.buffer)

	f.buffer = f.buffer[:0]
	f.flushing = false

	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := f.sendToFeedbackService(ctx, events); err != nil {
		log.Printf("[feedback] flush failed: %v", err)
	} else {
		log.Printf("[feedback] flushed %d events", len(events))
	}
}

func (f *FeedbackLoop) sendToFeedbackService(ctx context.Context, events []ThreatEvent) error {

	if len(events) == 0 {
		return nil
	}

	body, err := json.Marshal(map[string]interface{}{
		"events":    events,
		"timestamp": time.Now(),
	})
	if err != nil {
		return fmt.Errorf("marshal feedback: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		f.feedbackURL+"/events",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create feedback request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		// Non-fatal — feedback service may not be running
		log.Printf("[feedback] service unreachable: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[feedback] unexpected response status: %d", resp.StatusCode)
	}

	return nil
}