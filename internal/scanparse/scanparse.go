// Package scanparse turns the output of the security tools (grype, syft, oscap, cosign) into the
// compact structures the manager stores and shows. Parsing is deliberately tolerant of fields it
// does not know, because tool output evolves.
package scanparse

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// jsonBody trims log noise before the first "{" and after the last "}" (pod logs merge streams).
func jsonBody(b []byte) []byte {
	i, j := bytes.IndexByte(b, '{'), bytes.LastIndexByte(b, '}')
	if i < 0 || j < i {
		return b
	}
	return b[i : j+1]
}

// ---- grype ----

type Vuln struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"` // Critical | High | Medium | Low | Negligible | Unknown
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	FixedIn  []string `json:"fixedIn"`
	FixState string   `json:"fixState"`
	URL      string   `json:"url,omitempty"`
	Score    float64  `json:"score,omitempty"`
}

type VulnSummary struct {
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
	Negligible int    `json:"negligible"`
	Unknown    int    `json:"unknown"`
	Total      int    `json:"total"`
	Fixable    int    `json:"fixable"`
	DBBuilt    string `json:"dbBuilt,omitempty"`
}

type VulnReport struct {
	Summary VulnSummary `json:"summary"`
	Tool    string      `json:"tool"`
	Vulns   []Vuln      `json:"vulns"`
}

var sevRank = map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}

func normSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	}
	return "Unknown"
}

func ParseGrype(b []byte) (VulnReport, error) {
	var in struct {
		Matches []struct {
			Vulnerability struct {
				ID         string `json:"id"`
				Severity   string `json:"severity"`
				DataSource string `json:"dataSource"`
				Fix        struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				} `json:"fix"`
				CVSS []struct {
					Metrics struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"metrics"`
				} `json:"cvss"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"artifact"`
		} `json:"matches"`
		Descriptor struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			DB      struct {
				Status struct {
					Built string `json:"built"`
				} `json:"status"`
				Built string `json:"built"`
			} `json:"db"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(jsonBody(b), &in); err != nil {
		return VulnReport{}, fmt.Errorf("grype output is not JSON: %w", err)
	}
	r := VulnReport{Vulns: []Vuln{}}
	built := in.Descriptor.DB.Status.Built
	if built == "" {
		built = in.Descriptor.DB.Built
	}
	r.Summary.DBBuilt = built
	r.Tool = strings.TrimSpace("grype " + in.Descriptor.Version)
	seen := map[string]bool{}
	for _, m := range in.Matches {
		v := m.Vulnerability
		key := v.ID + "|" + m.Artifact.Name + "|" + m.Artifact.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		x := Vuln{ID: v.ID, Severity: normSeverity(v.Severity), Package: m.Artifact.Name, Version: m.Artifact.Version,
			Type: m.Artifact.Type, FixedIn: append([]string{}, v.Fix.Versions...), FixState: v.Fix.State, URL: safeURL(v.DataSource)}
		for _, c := range v.CVSS {
			if c.Metrics.BaseScore > x.Score {
				x.Score = c.Metrics.BaseScore
			}
		}
		r.Vulns = append(r.Vulns, x)
		r.Summary.Total++
		switch x.Severity {
		case "Critical":
			r.Summary.Critical++
		case "High":
			r.Summary.High++
		case "Medium":
			r.Summary.Medium++
		case "Low":
			r.Summary.Low++
		case "Negligible":
			r.Summary.Negligible++
		default:
			r.Summary.Unknown++
		}
		if len(x.FixedIn) > 0 {
			r.Summary.Fixable++
		}
	}
	sort.SliceStable(r.Vulns, func(i, j int) bool {
		a, b := r.Vulns[i], r.Vulns[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})
	return r, nil
}

// safeURL keeps only http(s) links: scan data is untrusted and ends up as href in the UI.
func safeURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.String()
}

// ---- syft / CycloneDX ----

type Component struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"` // ecosystem from the purl: apk, rpm, golang, npm, ...
	PURL     string   `json:"purl"`
	Licenses []string `json:"licenses,omitempty"`
}

type SBOMSummary struct {
	Packages int            `json:"packages"` // installed packages and libraries (files excluded)
	Files    int            `json:"files"`
	ByType   map[string]int `json:"byType"`
	Format   string         `json:"format"`
}

type SBOMReport struct {
	Summary    SBOMSummary `json:"summary"`
	Tool       string      `json:"tool"`
	Components []Component `json:"components"`
}

func ParseCycloneDX(b []byte) (SBOMReport, error) {
	var in struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Type     string `json:"type"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(jsonBody(b), &in); err != nil {
		return SBOMReport{}, fmt.Errorf("syft output is not JSON: %w", err)
	}
	if in.BOMFormat != "CycloneDX" {
		return SBOMReport{}, errors.New("syft output is not a CycloneDX document")
	}
	r := SBOMReport{Components: []Component{}, Tool: "syft"}
	r.Summary.Format = "CycloneDX " + in.SpecVersion
	r.Summary.ByType = map[string]int{}
	// tools is {components:[{name,version}]} in CycloneDX 1.5+, or a plain list before that.
	var t1 struct {
		Components []struct{ Name, Version string } `json:"components"`
	}
	var t0 []struct{ Name, Version string }
	if json.Unmarshal(in.Metadata.Tools, &t1) == nil && len(t1.Components) > 0 {
		r.Tool = strings.TrimSpace(t1.Components[0].Name + " " + t1.Components[0].Version)
	} else if json.Unmarshal(in.Metadata.Tools, &t0) == nil && len(t0) > 0 {
		r.Tool = strings.TrimSpace(t0[0].Name + " " + t0[0].Version)
	}
	for _, c := range in.Components {
		if c.Type == "file" { // individual files are noise in a package list; count them only
			r.Summary.Files++
			continue
		}
		x := Component{Name: c.Name, Version: c.Version, PURL: c.PURL, Type: purlType(c.PURL, c.Type)}
		for _, l := range c.Licenses {
			switch {
			case l.License.ID != "":
				x.Licenses = append(x.Licenses, l.License.ID)
			case l.License.Name != "":
				x.Licenses = append(x.Licenses, l.License.Name)
			case l.Expression != "":
				x.Licenses = append(x.Licenses, l.Expression)
			}
		}
		r.Components = append(r.Components, x)
		r.Summary.ByType[x.Type]++
	}
	r.Summary.Packages = len(r.Components)
	sort.SliceStable(r.Components, func(i, j int) bool { return r.Components[i].Name < r.Components[j].Name })
	return r, nil
}

func purlType(purl, fallback string) string {
	if strings.HasPrefix(purl, "pkg:") {
		rest := purl[4:]
		if i := strings.IndexAny(rest, "/@"); i > 0 {
			return rest[:i]
		}
	}
	if fallback == "" {
		return "other"
	}
	return fallback
}

// ---- openscap OVAL ----

type OVALFinding struct {
	Definition string   `json:"definition"`
	Advisory   string   `json:"advisory"` // e.g. RHSA-2026:1234
	Title      string   `json:"title"`
	Severity   string   `json:"severity"` // Critical | Important | Moderate | Low | Unknown
	CVEs       []string `json:"cves"`
	URL        string   `json:"url,omitempty"`
}

type OVALSummary struct {
	Applicable  bool   `json:"applicable"`
	Reason      string `json:"reason,omitempty"`
	OS          string `json:"os,omitempty"`
	Content     string `json:"content,omitempty"`
	Definitions int    `json:"definitions"`
	Vulnerable  int    `json:"vulnerable"`
	Critical    int    `json:"critical"`
	Important   int    `json:"important"`
	Moderate    int    `json:"moderate"`
	Low         int    `json:"low"`
}

type OVALReport struct {
	Summary  OVALSummary   `json:"summary"`
	Findings []OVALFinding `json:"findings"`
}

type ovalDef struct {
	ID       string `xml:"id,attr"`
	Title    string `xml:"metadata>title"`
	Severity string `xml:"metadata>advisory>severity"`
	Refs     []struct {
		Source string `xml:"source,attr"`
		RefID  string `xml:"ref_id,attr"`
		URL    string `xml:"ref_url,attr"`
	} `xml:"metadata>reference"`
	CVEs []struct {
		ID string `xml:",chardata"`
	} `xml:"metadata>advisory>cve"`
}

// ParseOVALResults streams an oscap results file. The file embeds every definition's metadata and
// the result for each one; definitions evaluated "true" are the advisories that apply to the image.
func ParseOVALResults(r io.Reader) (OVALReport, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	meta := map[string]ovalDef{}
	results := map[string]string{}
	var stack []string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return OVALReport{}, fmt.Errorf("oval results: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := t.Name.Local
			if n == "definition" && len(stack) >= 2 && stack[len(stack)-1] == "definitions" {
				switch stack[len(stack)-2] {
				case "oval_definitions":
					var d ovalDef
					if err := dec.DecodeElement(&d, &t); err != nil {
						return OVALReport{}, err
					}
					meta[d.ID] = d
					continue
				case "system":
					var id, res string
					for _, a := range t.Attr {
						switch a.Name.Local {
						case "definition_id":
							id = a.Value
						case "id":
							if id == "" {
								id = a.Value
							}
						case "result":
							res = a.Value
						}
					}
					if err := dec.Skip(); err != nil {
						return OVALReport{}, err
					}
					results[id] = res
					continue
				}
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	rep := OVALReport{Findings: []OVALFinding{}}
	rep.Summary.Applicable = true
	rep.Summary.Definitions = len(results)
	for id, res := range results {
		if res != "true" {
			continue
		}
		m := meta[id]
		f := OVALFinding{Definition: id, Title: m.Title, Severity: normOVALSeverity(m.Severity), CVEs: []string{}}
		for _, ref := range m.Refs {
			if strings.EqualFold(ref.Source, "RHSA") || strings.HasPrefix(ref.RefID, "RHSA-") || strings.HasPrefix(ref.RefID, "RHBA-") || strings.HasPrefix(ref.RefID, "RHEA-") {
				f.Advisory, f.URL = ref.RefID, safeURL(ref.URL)
				break
			}
		}
		for _, c := range m.CVEs {
			if id := strings.TrimSpace(c.ID); id != "" {
				f.CVEs = append(f.CVEs, id)
			}
		}
		rep.Findings = append(rep.Findings, f)
		rep.Summary.Vulnerable++
		switch f.Severity {
		case "Critical":
			rep.Summary.Critical++
		case "Important":
			rep.Summary.Important++
		case "Moderate":
			rep.Summary.Moderate++
		case "Low":
			rep.Summary.Low++
		}
	}
	rank := map[string]int{"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3, "Unknown": 4}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return a.Advisory > b.Advisory // newest advisories first
	})
	return rep, nil
}

func normOVALSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "important":
		return "Important"
	case "moderate":
		return "Moderate"
	case "low":
		return "Low"
	}
	return "Unknown"
}

// ---- cosign ----

type SigStatus string

const (
	SigSigned     SigStatus = "signed"     // verified with a trusted key
	SigUnsigned   SigStatus = "unsigned"   // no signature found
	SigInvalid    SigStatus = "invalid"    // a signature exists but no trusted key verifies it
	SigUnverified SigStatus = "unverified" // a signature exists but no trusted keys are configured
)

// ClassifyCosign interprets one `cosign verify` run. ok means the tool could classify the
// outcome; when it cannot (network error, bad credentials) the scan should fail instead.
func ClassifyCosign(exit int, stderr string) (verified bool, status SigStatus, ok bool) {
	if exit == 0 {
		return true, SigSigned, true
	}
	l := strings.ToLower(stderr)
	switch {
	case strings.Contains(l, "no signatures found"), strings.Contains(l, "no signatures associated"):
		return false, SigUnsigned, true
	case strings.Contains(l, "do not match threshold"), strings.Contains(l, "no matching signatures"),
		strings.Contains(l, "no matching attestations"), strings.Contains(l, "invalid signature"),
		strings.Contains(l, "crypto/ecdsa: verification error"):
		return false, SigInvalid, true
	}
	return false, "", false
}

// Tail returns the last n bytes of s as a single trimmed line, for error messages.
func Tail(b []byte, n int) string {
	b = bytes.TrimSpace(b)
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.Join(strings.Fields(string(b)), " ")
}
