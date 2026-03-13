// ml_client.go — HTTP client for the ML Detector (Stage I)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type MLClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewMLClient(baseURL string) *MLClient {
	return &MLClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type mlDetectRequest struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	ContentType string `json:"content_type"`
	Cookie      string `json:"cookie"`
	Length      int    `json:"length"`
	Content     string `json:"content"`
	Host        string `json:"host"`
}

type MLDetectResponse struct {
	Classification string    `json:"classification"`
	ThreatScore    float64   `json:"threat_score"`
	RFConfidence   float64   `json:"rf_confidence"`
	ISOFlag        int       `json:"iso_flag"`
	Features       []float64 `json:"features"`
	LatencyMs      float64   `json:"latency_ms"`
}

// Detect sends a request to the ML detector and returns the classification.
func (m *MLClient) Detect(ctx context.Context, req *InspectRequest) (*MLDetectResponse, error) {

	payload := mlDetectRequest{
		Method:      req.Method,
		URL:         req.URL,
		UserAgent:   req.UserAgent,
		ContentType: req.ContentType,
		Cookie:      req.Cookie,
		Length:      req.Length,
		Content:     req.Content,
		Host:        req.Host,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ML request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		m.baseURL+"/detect",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create ML request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ML detector unreachable (%s): %w", m.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ML detector returned status %d", resp.StatusCode)
	}

	var result MLDetectResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode ML response: %w", err)
	}

	return &result, nil
}

// HealthCheck verifies the ML detector is reachable.
func (m *MLClient) HealthCheck(ctx context.Context) error {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		m.baseURL+"/health",
		nil,
	)

	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ML detector unreachable (%s): %w", m.baseURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ML detector unhealthy: status %d", resp.StatusCode)
	}

	return nil
}