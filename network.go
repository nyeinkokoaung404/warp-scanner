package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

const (
	probeRetries      = 3
	probeTimeout      = 2 * time.Second
	probeConcurrency  = 128
	probeStaggerDelay = 10 * time.Millisecond
)

func scanEndpoints(endpoints []string) []ScanResult {
	bar := progressbar.NewOptions(len(endpoints), progressbar.OptionSetDescription("Scanning WARP IP endpoints"), progressbar.OptionSetPredictTime(false), progressbar.OptionFullWidth(), progressbar.OptionEnableColorCodes(true), progressbar.OptionSetTheme(progressbar.Theme{Saucer: "[green]#[reset]", SaucerPadding: " ", BarStart: "[", BarEnd: "]"}))
	results := make(chan ScanResult, len(endpoints))
	semaphore := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup

	for index, endpoint := range endpoints {
		wg.Add(1)
		go func(index int, endpoint string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			if index > 0 {
				time.Sleep(time.Duration(index%probeConcurrency) * probeStaggerDelay)
			}

			var successful int
			var totalLatency int64
			for attempt := 0; attempt < probeRetries; attempt++ {
				start := time.Now()
				dialer := net.Dialer{Timeout: probeTimeout}
				conn, err := dialer.Dial(endpointNetwork(endpoint), endpoint)
				latency := time.Since(start).Milliseconds()
				if err == nil {
					successful++
					totalLatency += latency
					_ = conn.Close()
				}
			}

			bar.Add(1)
			if successful == 0 {
				log.Printf("[%d] %s -> %s", index+1, endpoint, "Failed")
				return
			}
			loss := float64(probeRetries-successful) / float64(probeRetries) * 100
			result := ScanResult{Endpoint: endpoint, Loss: loss, Latency: totalLatency / int64(successful)}
			results <- result
			log.Printf("[%d] %s -> Success - Loss rate: %.1f %% - Avg. Latency: %d ms", index+1, endpoint, result.Loss, result.Latency)
		}(index, endpoint)
	}

	wg.Wait()
	close(results)
	fmt.Println()
	allResults := make([]ScanResult, 0, len(results))
	for result := range results {
		allResults = append(allResults, result)
	}
	return allResults
}

func endpointNetwork(endpoint string) string {
	if strings.HasPrefix(endpoint, "[") {
		return "tcp6"
	}
	return "tcp4"
}
