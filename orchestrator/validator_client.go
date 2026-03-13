// validator_client.go — submits proofs to the validator network (Stage III)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ValidatorClient struct {
	validatorURLs []string
	httpClient    *http.Client
}

func NewValidatorClient(urls []string) *ValidatorClient {

	var cleaned []string
	for _, u := range urls {
		cleaned = append(cleaned, strings.TrimSpace(u))
	}

	return &ValidatorClient{
		validatorURLs: cleaned,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type validatorVerifyRequest struct {
	RequestID      string    `json:"request_id"`
	ProofBytes     []byte    `json:"proof_bytes"`
	PublicInputs   [][]byte  `json:"public_inputs"`
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
	Timestamp      time.Time `json:"timestamp"`
}

type ValidatorVerifyResponse struct {
	RequestID  string `json:"request_id"`
	NodeID     int    `json:"node_id"`
	Valid      bool   `json:"valid"`
	Consensus  bool   `json:"consensus"`
	VoteCount  int    `json:"vote_count"`
	TotalNodes int    `json:"total_nodes"`
	LatencyMs  int64  `json:"latency_ms"`
}

// Submit sends a proof to the validator network.
// It tries validators sequentially until one successfully processes the request.
func (v *ValidatorClient) Submit(
	ctx context.Context,
	requestID string,
	proof *ZKPProofResponse,
	classification string,
	threatScore float64,
) (*ValidatorVerifyResponse, error) {

	payload := validatorVerifyRequest{
		RequestID:      requestID,
		ProofBytes:     proof.ProofBytes,
		PublicInputs:   proof.PublicInputs,
		Classification: classification,
		ThreatScore:    threatScore,
		Timestamp:      time.Now(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal validator request: %w", err)
	}

	var lastErr error

	for _, url := range v.validatorURLs {

		result, err := v.submitToValidator(ctx, url, body)
		if err != nil {
			lastErr = err
			continue
		}

		return result, nil
	}

	return nil, fmt.Errorf("all validators unreachable: %w", lastErr)
}

func (v *ValidatorClient) submitToValidator(
	ctx context.Context,
	baseURL string,
	body []byte,
) (*ValidatorVerifyResponse, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		baseURL+"/verify",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create validator request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("validator %s unreachable: %w", baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validator %s returned status %d", baseURL, resp.StatusCode)
	}

	var result ValidatorVerifyResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode validator response: %w", err)
	}

	return &result, nil
}

// HealthCheck verifies that at least one validator is reachable.
func (v *ValidatorClient) HealthCheck(ctx context.Context) error {

	for _, url := range v.validatorURLs {

		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			url+"/health",
			nil,
		)

		if err != nil {
			continue
		}

		resp, err := v.httpClient.Do(req)
		if err != nil {
			continue
		}

		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}
	}

	return fmt.Errorf("no validators reachable")
}