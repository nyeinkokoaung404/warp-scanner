package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"slices"

	"github.com/schollz/progressbar/v3"
)

var httpClient *http.Client

func initHttpClient(preferIPv6 bool) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 3 * time.Second,
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			for _, ip := range ips {
				if preferIPv6 {
					if ip.To4() == nil {
						return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
					}
				} else {
					if ip.To4() != nil {
						return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
					}
				}
			}

			return nil, fmt.Errorf("no suitable IP found for %s", host)
		},
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

// resolveTestTarget resolves the tunnel-test target once, using the system
// resolver, so the per-endpoint test does not depend on Xray's own DNS
// (8.8.8.8), which some networks block or intercept. The test is then made
// against the resolved IP with the original Host header, so Xray never has
// to resolve anything for the test itself. On failure it falls back to the
// hostname, i.e. the previous behaviour.
func resolveTestTarget() (targetURL, hostHeader string) {
	const host = "www.gstatic.com"
	// Resolve in the family the scan mode uses (the tunnel is dual-stack).
	network := "ip4"
	if scanConfig.Ipv6Mode && !scanConfig.Ipv4Mode {
		network = "ip6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		log.Printf("Warning: could not resolve %s (%v), testing by hostname", host, err)
		return "http://" + host + "/generate_204", host
	}
	targetURL = "http://" + ips[0].String() + "/generate_204"
	successMessage(fmt.Sprintf("Test target resolved: %s -> %s", host, ips[0].String()))
	return targetURL, host
}

func checkNetworkStats(preferIPv6 bool) {
	fmt.Printf("\n%s Determining network quality to adjust scan options...\n\n", prompt)
	const (
		testTargetURL     = "http://www.google.com/generate_204"
		initialTestCount  = 100
		goodLatencyMs     = 50
		moderateLatencyMs = 100
		poorLatencyMs     = 200
		acceptableLoss    = 5.0
		highLoss          = 10.0
		moderateJitterMs  = 5.0
		highJitterMs      = 10.0
		maxConcurrency    = 5
	)

	var (
		totalLatency       int64
		successCount       int
		wg                 sync.WaitGroup
		latencyResults     = make(chan int64, initialTestCount)
		concurrencyLimiter = make(chan struct{}, maxConcurrency)
	)

	networkMode := "IPv4"
	if preferIPv6 {
		networkMode = "IPv6"
	}
	desc := fmt.Sprintf("Testing %s network...", networkMode)
	bar := progressbar.NewOptions(initialTestCount,
		progressbar.OptionShowBytes(false),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetDescription(desc),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]#[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	initHttpClient(preferIPv6)
	for range initialTestCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrencyLimiter <- struct{}{}
			defer func() { <-concurrencyLimiter }()
			start := time.Now()
			resp, err := httpClient.Head(testTargetURL)
			bar.Add(1)
			latency := time.Since(start).Milliseconds()
			if err == nil && resp.StatusCode == http.StatusNoContent {
				if resp.Body != nil {
					resp.Body.Close()
				}
				latencyResults <- latency
			} else {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				latencyResults <- -1
			}
		}()
	}

	wg.Wait()
	close(latencyResults)
	fmt.Println()

	successfulLatencies := make([]int64, 0, successCount)
	for res := range latencyResults {
		if res >= 0 {
			successCount++
			totalLatency += res
			successfulLatencies = append(successfulLatencies, res)
		}
	}

	if successCount == 0 {
		failMessage("Initial network quality test failed. Could not reach test server.")
		fmt.Printf("\n%s Fallback to default scan settings.\n", prompt)
		return
	}

	slices.Sort(successfulLatencies)
	medianLatency := successfulLatencies[len(successfulLatencies)/2]
	lossRate := float64(initialTestCount-successCount) / float64(initialTestCount) * 100
	var avgJitter float64

	if successCount > 1 {
		var totalJitter int64
		for i := 0; i < len(successfulLatencies)-1; i++ {
			diff := successfulLatencies[i+1] - successfulLatencies[i]
			if diff < 0 {
				diff = -diff
			}
			totalJitter += diff
		}
		avgJitter = float64(totalJitter) / float64(successCount-1)
		fmt.Printf("\n%s Avg Latency: %dms | Jitter: %.1fms | Loss: %.1f%%\n", prompt, medianLatency, avgJitter, lossRate)
	} else {
		fmt.Printf("\n%s Avg Latency: %dms | Jitter not calculated (unsuccessful tests) | Loss: %.1f%%\n", prompt, medianLatency, lossRate)
	}

	if medianLatency >= int64(poorLatencyMs) || lossRate >= highLoss || (successCount > 1 && avgJitter >= highJitterMs) {
		if preferIPv6 {
			scanConfig.IPv6Retries = 7
		} else {
			scanConfig.IPv4Retries = 7
		}
		successMessage("Network appears slow/unstable.")
	} else if medianLatency >= int64(moderateLatencyMs) || lossRate >= acceptableLoss || (successCount > 1 && avgJitter >= moderateJitterMs) {
		if preferIPv6 {
			scanConfig.IPv6Retries = 5
		} else {
			scanConfig.IPv4Retries = 5
		}
		successMessage("Network is moderate or some packet loss detected.")
	} else {
		successMessage("Network quality seems good. Using default scan settings.")
	}
}

func scanEndpoints() ([]ScanResult, error) {
	testTargetURL, testTargetHost := resolveTestTarget()

	err := createXrayConfig()
	if err != nil {
		return nil, err
	}

	cmd, err := runXrayCore()
	if err != nil {
		log.Print(err)
		return nil, err
	}

	var wg sync.WaitGroup
	results := make(chan ScanResult, len(scanConfig.Endpoints))
	transports := make([]*http.Transport, len(scanConfig.Endpoints))

	for i, endpoint := range scanConfig.Endpoints {
		wg.Add(1)
		go func(endpoint string, portIdx int) {
			defer wg.Done()
			time.Sleep(time.Duration(portIdx*scanConfig.EndpointStaggeringMs) * time.Millisecond)
			proxyURL := must(url.Parse(fmt.Sprintf("http://127.0.0.1:%d", 1080+portIdx)))
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
			transports[portIdx] = transport

			currentRetries := scanConfig.IPv4Retries
			if scanConfig.Ipv6Mode && !scanConfig.Ipv4Mode ||
				scanConfig.Ipv4Mode && scanConfig.Ipv6Mode && i >= len(scanConfig.Endpoints)/2 {
				currentRetries = scanConfig.IPv6Retries
			}

			var successCount int
			var totalLatency int64

			var innerWg sync.WaitGroup
			latencies := make(chan int64, currentRetries)
			// Keep the failure reasons: "Failed" alone hides whether the
			// tunnel, the DNS, or the proxy is at fault.
			failures := make(chan string, currentRetries)

			for t := range currentRetries {
				innerWg.Add(1)
				go func(delay int) {
					defer innerWg.Done()
					time.Sleep(time.Duration(delay) * time.Millisecond)
					client := &http.Client{
						Timeout:   2 * time.Second,
						Transport: transport,
					}

					req, err := http.NewRequest("HEAD", testTargetURL, nil)
					if err != nil {
						failures <- err.Error()
						latencies <- -1
						return
					}
					// The URL may be an IP (see resolveTestTarget); the
					// Host header still names the real target so the
					// front-end answers 204.
					req.Host = testTargetHost

					start := time.Now()
					resp, err := client.Do(req)
					latency := time.Since(start).Milliseconds()
					if err != nil {
						failures <- err.Error()
						latencies <- -1
						return
					}
					if resp.Body != nil {
						resp.Body.Close()
					}
					if resp.StatusCode == 204 {
						latencies <- latency
					} else {
						failures <- fmt.Sprintf("HTTP %d", resp.StatusCode)
						latencies <- -1
					}
				}(t * scanConfig.RetryStaggeringMs)
			}
			innerWg.Wait()
			close(latencies)
			close(failures)

			for l := range latencies {
				if l >= 0 {
					successCount++
					totalLatency += l
				}
			}

			if successCount == 0 {
				lastErr := ""
				for e := range failures {
					lastErr = e
				}
				log.Printf("[%d] %s -> %s (%s)\n", i+1, fmtStr(endpoint, ORANGE, false), fmtStr("Failed", RED, true), lastErr)
			} else {
				avgLatency := totalLatency / int64(successCount)
				lossRate := float64(currentRetries-successCount) / float64(currentRetries) * 100
				results <- ScanResult{Endpoint: endpoint, Loss: lossRate, Latency: avgLatency}
				log.Printf("[%d] %s -> %s - %s %.1f %% - %s %d ms\n",
					i+1,
					fmtStr(endpoint, ORANGE, false),
					fmtStr("Success", GREEN, true),
					fmtStr("Loss rate:", "", true),
					lossRate,
					fmtStr("Avg. Latency:", "", true),
					avgLatency,
				)
			}
		}(endpoint, i)
	}
	wg.Wait()
	close(results)

	var allResults []ScanResult
	for r := range results {
		allResults = append(allResults, r)
	}

	if err := cmd.Process.Kill(); err != nil {
		return nil, fmt.Errorf("error killing Xray core: %w", err)
	}

	cmd.Wait()

	return allResults, nil
}
