package scanparse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const grypeSample = `{"matches":[
 {"vulnerability":{"id":"CVE-2021-3711","severity":"Critical","dataSource":"https://nvd.nist.gov/vuln/detail/CVE-2021-3711","fix":{"versions":["1.1.1l-r0"],"state":"fixed"},"cvss":[{"metrics":{"baseScore":9.8}},{"metrics":{"baseScore":7.1}}]},"artifact":{"name":"libssl1.1","version":"1.1.1k-r0","type":"apk"}},
 {"vulnerability":{"id":"CVE-2021-3711","severity":"Critical","fix":{"versions":[],"state":"unknown"}},"artifact":{"name":"libssl1.1","version":"1.1.1k-r0","type":"apk"}},
 {"vulnerability":{"id":"CVE-2022-0001","severity":"low","dataSource":"javascript:alert(1)","fix":{"versions":[],"state":"not-fixed"}},"artifact":{"name":"busybox","version":"1.31","type":"apk"}},
 {"vulnerability":{"id":"CVE-2022-0002","severity":"High","fix":{"versions":["2.0"],"state":"fixed"},"cvss":[{"metrics":{"baseScore":8.1}}]},"artifact":{"name":"zlib","version":"1.2","type":"apk"}},
 {"vulnerability":{"id":"GHSA-xxxx","severity":"weird","fix":{}},"artifact":{"name":"lib","version":"1","type":"go-module"}}
],"descriptor":{"name":"grype","version":"0.119.0","db":{"status":{"built":"2026-10-08T06:33:47Z"}}}}`

func TestParseGrype(t *testing.T) {
	r, err := ParseGrype([]byte(grypeSample))
	if err != nil {
		t.Fatal(err)
	}
	s := r.Summary
	if s.Total != 4 || s.Critical != 1 || s.High != 1 || s.Low != 1 || s.Unknown != 1 || s.Fixable != 2 {
		t.Fatalf("summary %+v (duplicate id+package must count once)", s)
	}
	if s.DBBuilt != "2026-10-08T06:33:47Z" || r.Tool != "grype 0.119.0" {
		t.Fatalf("metadata %+v %q", s, r.Tool)
	}
	if r.Vulns[0].ID != "CVE-2021-3711" || r.Vulns[0].Score != 9.8 || r.Vulns[1].ID != "CVE-2022-0002" {
		t.Fatalf("order/score: %+v", r.Vulns[:2])
	}
	for _, v := range r.Vulns {
		if v.ID == "CVE-2022-0001" && v.URL != "" {
			t.Fatal("javascript: URL must be dropped (it becomes an href in the UI)")
		}
	}
	if _, err := ParseGrype([]byte("Error: boom")); err == nil {
		t.Fatal("non-JSON accepted")
	}
	empty, err := ParseGrype([]byte(`{"matches":[]}`))
	if err != nil || empty.Vulns == nil || empty.Summary.Total != 0 {
		t.Fatalf("empty: %+v %v", empty, err)
	}
}

const cdxSample = `{"bomFormat":"CycloneDX","specVersion":"1.7","metadata":{"tools":{"components":[{"name":"syft","version":"1.54.1"}]}},
 "components":[
  {"name":"zlib","version":"1.2.11-r1","type":"library","purl":"pkg:apk/alpine/zlib@1.2.11-r1","licenses":[{"license":{"id":"Zlib"}}]},
  {"name":"github.com/x/y","version":"v1.0.0","type":"library","purl":"pkg:golang/github.com/x/y@v1.0.0","licenses":[{"expression":"MIT OR Apache-2.0"}]},
  {"name":"mystery","version":"","type":"file"}]}`

func TestParseCycloneDX(t *testing.T) {
	r, err := ParseCycloneDX([]byte(cdxSample))
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Packages != 2 || r.Summary.Files != 1 || r.Summary.ByType["apk"] != 1 || r.Summary.ByType["golang"] != 1 || r.Summary.ByType["file"] != 0 {
		t.Fatalf("summary %+v", r.Summary)
	}
	if r.Tool != "syft 1.54.1" || r.Summary.Format != "CycloneDX 1.7" {
		t.Fatalf("tool %q format %q", r.Tool, r.Summary.Format)
	}
	if r.Components[len(r.Components)-1].Licenses[0] != "Zlib" && r.Components[0].Licenses == nil {
		t.Fatalf("licenses lost: %+v", r.Components)
	}
	// legacy tools array
	old := strings.Replace(cdxSample, `{"components":[{"name":"syft","version":"1.54.1"}]}`, `[{"name":"syft","version":"0.9"}]`, 1)
	if r, err := ParseCycloneDX([]byte(old)); err != nil || r.Tool != "syft 0.9" {
		t.Fatalf("legacy tools: %q %v", r.Tool, err)
	}
	if _, err := ParseCycloneDX([]byte(`{"bomFormat":"SPDX"}`)); err == nil {
		t.Fatal("wrong format accepted")
	}
}

const ovalSample = `<?xml version="1.0"?>
<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
 <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
   <definition id="oval:com.redhat.rhsa:def:1" class="patch"><metadata><title>RHSA-2026:0001: openssl security update (Critical)</title>
     <reference source="RHSA" ref_id="RHSA-2026:0001" ref_url="https://access.redhat.com/errata/RHSA-2026:0001"/>
     <reference source="CVE" ref_id="CVE-2026-1" ref_url="https://x"/>
     <advisory><severity>Critical</severity><cve href="https://access.redhat.com/security/cve/CVE-2026-1">CVE-2026-1</cve><cve>CVE-2026-2</cve></advisory></metadata></definition>
   <definition id="oval:com.redhat.rhsa:def:2" class="patch"><metadata><title>RHSA-2026:0002: kernel (Moderate)</title>
     <reference source="RHSA" ref_id="RHSA-2026:0002" ref_url="javascript:alert(1)"/><advisory><severity>Moderate</severity></advisory></metadata></definition>
   <definition id="oval:com.redhat.rhsa:def:3" class="patch"><metadata><title>fixed already</title><advisory><severity>Important</severity></advisory></metadata></definition>
  </definitions>
 </oval_definitions>
 <results><system>
  <definitions>
   <definition definition_id="oval:com.redhat.rhsa:def:1" result="true" version="1"><criteria operator="AND" result="true"/></definition>
   <definition definition_id="oval:com.redhat.rhsa:def:2" result="true" version="1"/>
   <definition definition_id="oval:com.redhat.rhsa:def:3" result="false" version="1"/>
  </definitions>
 </system></results>
</oval_results>`

func TestParseOVALResults(t *testing.T) {
	r, err := ParseOVALResults(strings.NewReader(ovalSample))
	if err != nil {
		t.Fatal(err)
	}
	s := r.Summary
	if !s.Applicable || s.Definitions != 3 || s.Vulnerable != 2 || s.Critical != 1 || s.Moderate != 1 || s.Important != 0 {
		t.Fatalf("summary %+v", s)
	}
	f := r.Findings[0]
	if f.Advisory != "RHSA-2026:0001" || f.Severity != "Critical" || len(f.CVEs) != 2 || f.CVEs[0] != "CVE-2026-1" || f.URL == "" {
		t.Fatalf("finding %+v", f)
	}
	if r.Findings[1].URL != "" {
		t.Fatal("javascript: URL must be dropped")
	}
	if _, err := ParseOVALResults(strings.NewReader("<oval_results><oops")); err == nil {
		t.Fatal("truncated XML accepted")
	}
}

func TestClassifyCosign(t *testing.T) {
	for _, c := range []struct {
		exit   int
		stderr string
		want   SigStatus
		ok     bool
	}{
		{0, "", SigSigned, true},
		{1, "Error: no signatures found\nerror during command execution: no signatures found", SigUnsigned, true},
		{1, "Error: no matching attestations: failed to verify signature: could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1", SigInvalid, true},
		{1, "UNAUTHORIZED: authentication required", "", false},
		{1, "dial tcp: connection refused", "", false},
	} {
		_, st, ok := ClassifyCosign(c.exit, c.stderr)
		if st != c.want || ok != c.ok {
			t.Errorf("%q -> %q/%v, want %q/%v", c.stderr, st, ok, c.want, c.ok)
		}
	}
}

// TestRealToolOutput runs the parsers over genuine grype/syft/oscap output when available:
//
//	SCANPARSE_SAMPLES=/dir go test ./internal/scanparse   (dir holds vuln-alpine.json, sbom-alpine.json, results.xml)
func TestRealToolOutput(t *testing.T) {
	dir := os.Getenv("SCANPARSE_SAMPLES")
	if dir == "" {
		t.Skip("set SCANPARSE_SAMPLES to run against real tool output")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "vuln-alpine.json")); err == nil {
		r, err := ParseGrype(b)
		if err != nil || r.Summary.Total < 50 || r.Summary.Critical == 0 {
			t.Fatalf("real grype: %+v %v", r.Summary, err)
		}
		t.Logf("grype: %+v", r.Summary)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "sbom-alpine.json")); err == nil {
		r, err := ParseCycloneDX(b)
		if err != nil || r.Summary.Packages < 10 {
			t.Fatalf("real syft: %+v %v", r.Summary, err)
		}
		t.Logf("syft: %+v tool=%s", r.Summary, r.Tool)
	}
	if f, err := os.Open(filepath.Join(dir, "results.xml")); err == nil {
		defer f.Close()
		r, err := ParseOVALResults(f)
		if err != nil || r.Summary.Definitions < 1000 || r.Summary.Vulnerable == 0 {
			t.Fatalf("real oscap: %+v %v", r.Summary, err)
		}
		t.Logf("oval: %+v first=%+v", r.Summary, r.Findings[0])
	}
}
