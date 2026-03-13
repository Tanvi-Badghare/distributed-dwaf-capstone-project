// taxii_publisher.go — publishes verified threats to the TAXII server (Stage IV)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type TAXIIPublisher struct {
	baseURL    string
	httpClient *http.Client
}

func NewTAXIIPublisher(baseURL string) *TAXIIPublisher {
	return &TAXIIPublisher{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type taxiiThreatPayload struct {
	RequestID      string    `json:"request_id"`
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
	Method         string    `json:"method"`
	URL            string    `json:"url"`
	SourceApp      string    `json:"source_app"`
	ProofValid     bool      `json:"proof_valid"`
	Consensus      bool      `json:"consensus"`
	Timestamp      time.Time `json:"timestamp"`
}

type TAXIIPublishResponse struct {
	Published bool   `json:"published"`
	BundleID  string `json:"bundle_id"`
}

// Publish sends a verified threat to the TAXII server for STIX bundle creation.
// Only called when classification=malicious AND consensus=true AND proof_valid=true.
func (t *TAXIIPublisher) Publish(
	ctx context.Context,
	req *InspectRequest,
	result *InspectResult,
) (*TAXIIPublishResponse, error) {

	payload := taxiiThreatPayload{
		RequestID:      req.RequestID,
		Classification: result.Classification,
		ThreatScore:    result.ThreatScore,
		Method:         req.Method,
		URL:            req.URL,
		SourceApp:      req.SourceApp,
		ProofValid:     result.ProofValid,
		Consensus:      result.Consensus,
		Timestamp:      time.Now(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal taxii payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.baseURL+"/publish",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create taxii request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		// TAXII failure should NOT break the pipeline
		log.Printf("[taxii] publish failed: %v", err)
		return &TAXIIPublishResponse{Published: false}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[taxii] unexpected status: %d", resp.StatusCode)
		return &TAXIIPublishResponse{Published: false}, nil
	}

	// Limit response size to avoid large payload attacks
	limitedBody := io.LimitReader(resp.Body, 1<<20) // 1MB

	var result2 TAXIIPublishResponse
	if err := json.NewDecoder(limitedBody).Decode(&result2); err != nil {
		log.Printf("[taxii] decode response failed: %v", err)
		return &TAXIIPublishResponse{Published: false}, nil
	}

	return &result2, nil
}