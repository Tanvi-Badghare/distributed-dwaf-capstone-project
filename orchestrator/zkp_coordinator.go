// zkp_coordinator.go — HTTP client for the ZKP Layer (Stage II)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ZKPCoordinator struct {
	baseURL    string
	httpClient *http.Client
}

func NewZKPCoordinator(baseURL string) *ZKPCoordinator {
	return &ZKPCoordinator{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // Groth16 proof generation may take ~2s+
		},
	}
}

type zkpGenerateRequest struct {
	Features       []float64 `json:"features"`
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
}

type ZKPProofResponse struct {
	ProofBytes   []byte   `json:"proof_bytes"`
	PublicInputs [][]byte `json:"public_inputs"`
	LatencyMs    int64    `json:"latency_ms"`
}

// GenerateProof calls the ZKP layer to generate a Groth16 proof.
func (z *ZKPCoordinator) GenerateProof(
	ctx context.Context,
	features []float64,
	classification string,
	threatScore float64,
) (*ZKPProofResponse, error) {

	payload := zkpGenerateRequest{
		Features:       features,
		Classification: classification,
		ThreatScore:    threatScore,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ZKP request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		z.baseURL+"/generate-proof",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create ZKP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ZKP layer unreachable (%s): %w", z.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ZKP layer returned status %d", resp.StatusCode)
	}

	var result ZKPProofResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode ZKP response: %w", err)
	}

	return &result, nil
}

// HealthCheck verifies that the ZKP layer is reachable.
func (z *ZKPCoordinator) HealthCheck(ctx context.Context) error {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		z.baseURL+"/health",
		nil,
	)

	if err != nil {
		return err
	}

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ZKP layer unreachable (%s): %w", z.baseURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ZKP layer unhealthy: status %d", resp.StatusCode)
	}

	return nil
}