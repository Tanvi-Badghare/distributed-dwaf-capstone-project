// zkp_verifier.go — calls the ZKP layer REST API to verify proofs
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ZKPVerifier communicates with the ZKP verification service
type ZKPVerifier struct {
	baseURL    string
	httpClient *http.Client
}

// NewZKPVerifier initializes the verifier client
func NewZKPVerifier(baseURL string) *ZKPVerifier {

	return &ZKPVerifier{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ── Internal API Types ────────────────────────────────────────────────────────

type zkpVerifyRequest struct {
	ProofBytes   []byte   `json:"proof_bytes"`
	PublicInputs [][]byte `json:"public_inputs"`
}

type zkpVerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// ── Proof Verification ────────────────────────────────────────────────────────

// VerifyProof sends proof data to the ZKP layer for Groth16 verification
func (z *ZKPVerifier) VerifyProof(
	ctx context.Context,
	proofBytes []byte,
	publicInputs [][]byte,
) (bool, error) {

	if len(proofBytes) == 0 {
		return false, fmt.Errorf("empty proof received")
	}

	payload := zkpVerifyRequest{
		ProofBytes:   proofBytes,
		PublicInputs: publicInputs,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal proof request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		z.baseURL+"/verify-proof",
		bytes.NewReader(body),
	)
	if err != nil {
		return false, fmt.Errorf("failed to create verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("zkp layer unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		bodyBytes, _ := io.ReadAll(resp.Body)

		return false, fmt.Errorf(
			"zkp verification failed: status=%d response=%s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var result zkpVerifyResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode verification response: %w", err)
	}

	return result.Valid, nil
}

// ── Health Check ─────────────────────────────────────────────────────────────

// HealthCheck verifies if the ZKP layer service is reachable
func (z *ZKPVerifier) HealthCheck(ctx context.Context) error {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		z.baseURL+"/health",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("zkp layer unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("zkp layer unhealthy: status %d", resp.StatusCode)
	}

	return nil
}