package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

func banner(noColor bool) {
        art := `  ____              _______     
 |  _ \ _   _  ___ |__   __|   _ 
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|`

        if noColor {
                fmt.Println(art)
        } else {
                fmt.Println(cCyan + cBold + art + cReset)
        }
        fmt.Println()
}

func sectionHeader(noColor bool, title, info string) {
        line := strings.Repeat("-", 72)
        fmt.Println()
        fmt.Println(colorize(noColor, cCyan+cBold, line))
        fmt.Println(colorize(noColor, cCyan+cBold, "  "+title))
        if info != "" {
                for _, l := range strings.Split(info, "\n") {
                        if !strings.HasPrefix(l, "  ") {
                                l = "  " + l
                        }
                        fmt.Println(colorize(noColor, cGray, l))
                }
        }
        fmt.Println(colorize(noColor, cCyan+cBold, line))
}

func printRunHeader(cfg Config, doSub, doDir bool) {
        var lines []string
        lines = append(lines, "mode: "+cfg.Mode)
        if doSub {
                lines = append(lines, "sub target: "+cfg.Domain)
                lines = append(lines, "sub wordlist: "+tail(cfg.SubWL, 52))
        }
        if doDir {
                lines = append(lines, "dir target: "+cfg.BaseURL)
                lines = append(lines, "dir wordlist: "+tail(cfg.DirWL, 52))
        }

        rate := "unlimited"
        if cfg.Rate > 0 {
                rate = fmt.Sprintf("%d/s", cfg.Rate)
        }
        lines = append(lines, fmt.Sprintf("threads: %d   rate: %s   retries: %d", cfg.Threads, rate, cfg.Retries))
        if cfg.OutFile != "" {
                lines = append(lines, "output: "+cfg.OutFile)
        }
        sectionHeader(cfg.NoColor, "RUN", strings.Join(lines, "\n"))
}

func printSubHeader(cfg Config) {
        hdr := cell("SUBDOMAIN", wSub) + sep + cell("IP(s)", wIP) + sep + cell("CNAME", wCName)
        rule := cell(strings.Repeat("-", wSub), wSub) + sep + cell(strings.Repeat("-", wIP), wIP) + sep + cell(strings.Repeat("-", wCName), wCName)
        fmt.Println(colorize(cfg.NoColor, cBold, hdr))
        fmt.Println(colorize(cfg.NoColor, cGray, rule))
}

func printSubRow(cfg Config, r SubResult) {
        sc := colorize(cfg.NoColor, cGreen, cell(r.FQDN, wSub))
        ic := cell(strings.Join(r.IPs, ", "), wIP)
        cc := colorize(cfg.NoColor, cCyan, cell(r.CNAME, wCName))
        fmt.Println(sc + sep + ic + sep + cc)
}

func printSubTable(cfg Config, results []SubResult) {
        if len(results) == 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, "  (no subdomains resolved)"))
                return
        }
        printSubHeader(cfg)
        for _, r := range results {
                printSubRow(cfg, r)
        }
}

func printDirHeader(cfg Config) {
        hdr := cell("CODE", wCode) + sep +
                cellRight("SIZE", wSize) + sep +
                cellRight("WORDS", wWords) + sep +
                cellRight("LINES", wLines) + sep +
                cell("PATH", wPath) + sep +
                cell("NOTE", wNote)
        rule := cell(strings.Repeat("-", wCode), wCode) + sep +
                cellRight(strings.Repeat("-", wSize), wSize) + sep +
                cellRight(strings.Repeat("-", wWords), wWords) + sep +
                cellRight(strings.Repeat("-", wLines), wLines) + sep +
                cell(strings.Repeat("-", wPath), wPath) + sep +
                cell(strings.Repeat("-", wNote), wNote)
        fmt.Println(colorize(cfg.NoColor, cBold, hdr))
        fmt.Println(colorize(cfg.NoColor, cGray, rule))
}

func printDirRow(cfg Config, r dirResult) {
        plain := cell(strconv.Itoa(r.Status), wCode) + sep +
                cellRight(humanSize(r.Size), wSize) + sep +
                cellRight(strconv.Itoa(r.Words), wWords) + sep +
                cellRight(strconv.Itoa(r.Lines), wLines) + sep +
                cell(r.Path, wPath) + sep +
                cell(buildNote(r), wNote)
        fmt.Println(colorize(cfg.NoColor, colorForStatus(r.Status), plain))
}

func printDirTable(cfg Config, results []dirResult) {
        if len(results) == 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, "  (no paths matched filters)"))
                return
        }
        printDirHeader(cfg)
        for _, r := range results {
                printDirRow(cfg, r)
        }
}

// ---------------------------------------------------------------------------
// Summary + JSON output
// ---------------------------------------------------------------------------

func printSummary(cfg Config, doSub, doDir bool, subs []SubResult, dirs []dirResult, wc WildcardInfo, soft Soft404Info, dur time.Duration) {
        sectionHeader(cfg.NoColor, "SUMMARY", "")
        fmt.Printf("  mode              : %s\n", cfg.Mode)
        if doSub {
                fmt.Printf("  sub target        : %s\n", cfg.Domain)
                line := fmt.Sprintf("  subdomains found  : %d", len(subs))
                if wc.Detected {
                        line += fmt.Sprintf("   (wildcard: yes, filtered %d)", wc.Filtered)
                } else {
                        line += "   (wildcard: no)"
                }
                fmt.Println(line)
        }
        if doDir {
                fmt.Printf("  dir target        : %s\n", cfg.BaseURL)
                line := fmt.Sprintf("  directories found : %d", len(dirs))
                if soft.Detected || soft.Filtered > 0 {
                        line += fmt.Sprintf("   (soft-404: yes, filtered %d)", soft.Filtered)
                } else {
                        line += "   (soft-404: no)"
                }
                fmt.Println(line)
        }
        rate := "unlimited"
        if cfg.Rate > 0 {
                rate = fmt.Sprintf("%d/s", cfg.Rate)
        }
        fmt.Printf("  duration          : %.2fs\n", dur.Seconds())
        fmt.Printf("  rate              : %s\n", rate)
        fmt.Printf("  retries           : %d\n", cfg.Retries)
        if cfg.OutFile != "" {
                fmt.Printf("  output            : %s\n", cfg.OutFile)
        }
        fmt.Println(colorize(cfg.NoColor, cCyan+cBold, strings.Repeat("-", 72)))
}

func writeReport(cfg Config, subs []SubResult, dirs []dirResult, wc WildcardInfo, soft Soft404Info, started time.Time, dur time.Duration) error {
        if subs == nil {
                subs = []SubResult{}
        }
        if dirs == nil {
                dirs = []dirResult{}
        }
        var rep Report
        rep.Target.Domain = cfg.Domain
        rep.Target.BaseURL = cfg.BaseURL
        rep.StartedAt = started.Format(time.RFC3339)
        rep.Duration = dur.String()
        if wc.Detected || wc.Filtered > 0 {
                w := wc
                rep.Wildcard = &w
        }
        if soft.Detected || soft.Filtered > 0 {
                s := soft
                rep.Soft404 = &s
        }
        rep.Subdomains = subs
        rep.Directories = dirs
        rep.Summary = Summary{
                TotalSubdomains:  len(subs),
                TotalDirectories: len(dirs),
                Wildcard:         wc.Detected,
                Soft404:          soft.Detected,
                DurationSeconds:  dur.Seconds(),
        }
        b, err := json.MarshalIndent(rep, "", "  ")
        if err != nil {
                return err
        }
        return os.WriteFile(cfg.OutFile, b, 0644)
}
