package main

type SubResult struct {
	FQDN  string   `json:"fqdn"`
        IPs   []string `json:"ips"`
        CNAME string   `json:"cname,omitempty"`
}

type dirResult struct {
        Path        string `json:"path"`
        URL         string `json:"url"`
        Status      int    `json:"status"`
        Size        int64  `json:"size"`
        Words       int    `json:"words,omitempty"`
        Lines       int    `json:"lines,omitempty"`
        BodyHash    string `json:"body_hash,omitempty"`
        Location    string `json:"location,omitempty"`
        ContentType string `json:"content_type,omitempty"`
        Err         string `json:"error,omitempty"`
        matchRegex  bool
        filterRegex bool
}

type WildcardInfo struct {
        Detected bool     `json:"detected"`
        IPs      []string `json:"ips,omitempty"`
        Filtered int      `json:"filtered_noise"`
}

type Soft404Info struct {
        Detected bool   `json:"detected"`
        Note     string `json:"note,omitempty"`
        Filtered int    `json:"filtered_noise"`
}

type soft404Sig struct {
	status int
	size   int64
}

type dirCandidate struct {
	Path   string `json:"path"`
	Depth  int    `json:"depth"`
	Parent string `json:"parent,omitempty"`
}

type Summary struct {
        TotalSubdomains  int     `json:"total_subdomains"`
        TotalDirectories int     `json:"total_directories"`
        Wildcard         bool    `json:"wildcard"`
        Soft404          bool    `json:"soft_404"`
        DurationSeconds  float64 `json:"duration_seconds"`
}

type Report struct {
	Target struct {
		Domain  string `json:"domain,omitempty"`
                BaseURL string `json:"base_url,omitempty"`
        } `json:"target"`
        StartedAt   string        `json:"started_at"`
        Duration    string        `json:"duration"`
        Wildcard    *WildcardInfo `json:"wildcard,omitempty"`
        Soft404     *Soft404Info  `json:"soft_404,omitempty"`
        Subdomains  []SubResult   `json:"subdomains"`
        Directories []dirResult   `json:"directories"`
	Summary     Summary       `json:"summary"`
}
