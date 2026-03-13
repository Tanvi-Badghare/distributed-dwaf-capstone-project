// traffic_aggregator.go — collects HTTP traffic from federated testbed apps
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type TrafficAggregator struct {
	appURLs    []string
	httpClient *http.Client
	orch       *Orchestrator
}

func NewTrafficAggregator(appURLs []string, orch *Orchestrator) *TrafficAggregator {

	var cleaned []string
	for _, u := range appURLs {
		cleaned = append(cleaned, strings.TrimSpace(u))
	}

	return &TrafficAggregator{
		appURLs: cleaned,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		orch: orch,
	}
}

type appTrafficEntry struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	ContentType string `json:"content_type"`
	Cookie      string `json:"cookie"`
	Length      int    `json:"length"`
	Content     string `json:"content"`
	Host        string `json:"host"`
	SourceApp   string `json:"source_app"`
}

// PollAll fetches pending traffic entries from all registered testbed apps.
// Each app exposes a /traffic endpoint returning buffered HTTP requests.
func (ta *TrafficAggregator) PollAll(ctx context.Context) ([]*InspectRequest, error) {

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		all      []*InspectRequest
	)

	for _, appURL := range ta.appURLs {

		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			entries, err := ta.pollApp(ctx, url)
			if err != nil {
				log.Printf("[aggregator] failed to poll %s: %v", url, err)
				return
			}

			mu.Lock()
			all = append(all, entries...)
			mu.Unlock()

		}(appURL)
	}

	wg.Wait()

	return all, nil
}

func (ta *TrafficAggregator) pollApp(ctx context.Context, appURL string) ([]*InspectRequest, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appURL+"/traffic", nil)
	if err != nil {
		return nil, err
	}

	resp, err := ta.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("app %s unreachable: %w", appURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("app %s returned %d", appURL, resp.StatusCode)
	}

	// Protect against huge responses
	limitedBody := io.LimitReader(resp.Body, 10<<20) // 10MB

	var entries []appTrafficEntry

	if err := json.NewDecoder(limitedBody).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode traffic: %w", err)
	}

	requests := make([]*InspectRequest, 0, len(entries))

	for i, e := range entries {

		requests = append(requests, &InspectRequest{
			RequestID:   fmt.Sprintf("%s-%d-%d", e.SourceApp, time.Now().UnixNano(), i),
			Method:      e.Method,
			URL:         e.URL,
			UserAgent:   e.UserAgent,
			ContentType: e.ContentType,
			Cookie:      e.Cookie,
			Length:      e.Length,
			Content:     e.Content,
			Host:        e.Host,
			SourceApp:   e.SourceApp,
		})
	}

	return requests, nil
}