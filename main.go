package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

const (
	RED    = "1"
	GREEN  = "2"
	ORANGE = "208"
	BLUE   = "39"
)

type ScanConfig struct {
	EndpointCount int
	Ipv4Mode      bool
	Ipv6Mode      bool
	OutputCount   int
}

var (
	VERSION    = "dev"
	prompt     = fmtStr("●", GREEN, true)
	errMark    = fmtStr("✗", RED, true)
	succMark   = fmtStr("✓", GREEN, true)
	scanConfig = ScanConfig{EndpointCount: 100, Ipv4Mode: true}
)

type ScanResult struct {
	Endpoint string
	Loss     float64
	Latency  int64
}

func fmtStr(str, color string, isBold bool) string {
	style := lipgloss.NewStyle().Bold(isBold)
	if color != "" {
		style = style.Foreground(lipgloss.Color(color))
	}
	return style.Render(str)
}

func renderHeader() {
	fmt.Printf("\n%s %s\n", fmtStr("Warp IP Scanner", BLUE, true), fmtStr(VERSION, GREEN, false))
}

func generateEndpoints() {
	ports := []int{500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}
	ipv4Prefixes := []string{"188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.", "162.159.192.", "162.159.193.", "162.159.195.", "8.34.146.", "8.39.214.", "8.39.204.", "8.6.112.", "8.35.211.", "8.39.125.", "8.47.69."}
	ipv6Prefixes := []string{"2606:4700:d0::", "2606:4700:d1::"}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	endpoints := make([]string, 0, scanConfig.EndpointCount)
	seen := make(map[string]struct{})
	ipv4Count, ipv6Count := 0, 0
	if scanConfig.Ipv4Mode && scanConfig.Ipv6Mode {
		ipv4Count = scanConfig.EndpointCount / 2
		ipv6Count = scanConfig.EndpointCount - ipv4Count
	} else if scanConfig.Ipv4Mode {
		ipv4Count = scanConfig.EndpointCount
	} else {
		ipv6Count = scanConfig.EndpointCount
	}

	for len(endpoints) < ipv4Count {
		endpoint := fmt.Sprintf("%s%d:%d", ipv4Prefixes[r.Intn(len(ipv4Prefixes))], r.Intn(256), ports[r.Intn(len(ports))])
		if _, ok := seen[endpoint]; !ok {
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
	}
	for len(endpoints) < ipv4Count+ipv6Count {
		ip := fmt.Sprintf("%s%x:%x:%x:%x", ipv6Prefixes[r.Intn(len(ipv6Prefixes))], r.Intn(65536), r.Intn(65536), r.Intn(65536), r.Intn(65536))
		endpoint := fmt.Sprintf("[%s]:%d", ip, ports[r.Intn(len(ports))])
		if _, ok := seen[endpoint]; !ok {
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
	}
	scanConfigEndpoints = endpoints
	successMessage(fmt.Sprintf("Generated %d WARP IP endpoints to test", len(endpoints)))
}

var scanConfigEndpoints []string

func renderEndpoints(results []ScanResult) {
	successMessage(fmt.Sprintf("Top %d endpoints:", len(results)))
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, []string{result.Endpoint, fmt.Sprintf("%.1f %%", result.Loss), fmt.Sprintf("%d ms", result.Latency)})
	}
	t := table.New().Border(lipgloss.MarkdownBorder()).BorderTop(true).BorderBottom(true).BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color(GREEN))).Headers("Endpoint", "Loss rate", "Latency").Rows(rows...)
	fmt.Println(t.Render())
}

func checkNum(value string, min, max int) (bool, int) {
	number, err := strconv.Atoi(value)
	return err == nil && number >= min && number <= max, number
}

func failMessage(message string)    { fmt.Printf("%s %s\n", errMark, message) }
func successMessage(message string) { fmt.Printf("\n%s %s\n", succMark, message) }

func main() {
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()
	if *showVersion {
		fmt.Println(VERSION)
		return
	}

	renderHeader()
	fmt.Println("\nSelect scan mode:")
	fmt.Println("1. Quick scan - 100 endpoints")
	fmt.Println("2. Normal scan - 1000 endpoints")
	fmt.Println("3. Deep scan - 10000 endpoints")
	fmt.Println("4. Custom scan")
	for {
		fmt.Printf("\n%s Scan mode (1-4): ", prompt)
		var mode string
		fmt.Scanln(&mode)
		switch mode {
		case "1":
			scanConfig.EndpointCount = 100
		case "2":
			scanConfig.EndpointCount = 1000
		case "3":
			scanConfig.EndpointCount = 10000
		case "4":
			for {
				fmt.Printf("%s Endpoint count (1-10000): ", prompt)
				var count string
				fmt.Scanln(&count)
				if valid, number := checkNum(count, 1, 10000); valid {
					scanConfig.EndpointCount = number
					break
				}
				failMessage("Please enter a number between 1 and 10000.")
			}
		default:
			failMessage("Please select 1 to 4.")
			continue
		}
		break
	}

	fmt.Println("\nSelect IP version:")
	fmt.Println("1. IPv4 only")
	fmt.Println("2. IPv6 only")
	fmt.Println("3. IPv4 and IPv6")
	for {
		fmt.Printf("\n%s IP version (1-3): ", prompt)
		var version string
		fmt.Scanln(&version)
		switch version {
		case "1":
			scanConfig.Ipv4Mode, scanConfig.Ipv6Mode = true, false
		case "2":
			scanConfig.Ipv4Mode, scanConfig.Ipv6Mode = false, true
		case "3":
			scanConfig.Ipv4Mode, scanConfig.Ipv6Mode = true, true
		default:
			failMessage("Please select 1 to 3.")
			continue
		}
		break
	}

	generateEndpoints()
	results := scanEndpoints(scanConfigEndpoints)
	sort.Slice(results, func(i, j int) bool { return results[i].Latency < results[j].Latency })
	lines := []string{"Endpoint,Loss rate,Avg. Latency"}
	for _, result := range results {
		lines = append(lines, fmt.Sprintf("%s,%.2f %%,%d ms", result.Endpoint, result.Loss, result.Latency))
	}
	if err := os.WriteFile("result.csv", []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		log.Printf("Error saving result.csv: %v", err)
	}

	outputCount := scanConfig.OutputCount
	if outputCount == 0 || outputCount > len(results) {
		outputCount = len(results)
	}
	renderEndpoints(results[:outputCount])
	successMessage(fmt.Sprintf("Scan completed. Found %d reachable WARP endpoints. Results saved to result.csv.", len(results)))
}
