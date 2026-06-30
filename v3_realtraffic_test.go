package xarf

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// These tests pin xarf-go's v3→v4 conversion to the XARF v3 dialect actually
// seen in production (the spellings and field names in the deployed v3 schema:
// DOS/PortScan/LoginAttack, SourceUrl, no Protocol field). They are the
// contract for feat/v3-converter-real-traffic. See also v3_compat_test.go,
// which covers the older JS-mirrored spellings (kept as aliases).

// mkV3 builds a v3 report envelope around a Report body.
func mkV3(report map[string]interface{}) []byte {
	doc := map[string]interface{}{
		"Version":    "3",
		"Disclosure": true,
		"ReporterInfo": map[string]interface{}{
			"ReporterOrg":       "Test Reporter",
			"ReporterOrgDomain": "reporter.example",
			"ReporterOrgEmail":  "abuse@reporter.example",
		},
		"Report": report,
	}
	b, _ := json.Marshal(doc)
	return b
}

func parseV3(t *testing.T, body []byte) ParseResult {
	t.Helper()
	res, err := Parse(body, &ParseOptions{Strict: false})
	if err != nil {
		t.Fatalf("Parse returned a hard error (malformed/oversize): %v", err)
	}
	return res
}

// TestV3RealTraffic_ConvertibleTypes asserts the six v3 ReportTypes that map to
// a v4.2.0 type whose required fields the converter can populate from v3 data.
func TestV3RealTraffic_ConvertibleTypes(t *testing.T) {
	cases := []struct {
		name     string
		report   map[string]interface{}
		wantCat  string
		wantType string
	}{
		{
			name: "Phishing (content, SourceUrl only)",
			report: map[string]interface{}{
				"ReportClass": "Content", "ReportType": "Phishing",
				"Date": "2026-06-23T06:55:10Z", "SourceUrl": "https://bad.example/login.php",
			},
			wantCat: "content", wantType: "phishing",
		},
		{
			name: "Malware (content, SourceUrl only)",
			report: map[string]interface{}{
				"ReportClass": "Content", "ReportType": "Malware",
				"Date": "2026-06-23T06:55:10Z", "SourceUrl": "https://bad.example/dropper.exe",
			},
			wantCat: "content", wantType: "malware",
		},
		{
			name: "DOS (connection)",
			report: map[string]interface{}{
				"ReportClass": "Activity", "ReportType": "DOS",
				"Date": "2026-06-23T06:55:10Z", "SourceIp": "203.0.113.10", "SourcePort": 12345,
				"DestinationIp": "198.51.100.5", "DestinationPort": 80,
			},
			wantCat: "connection", wantType: "ddos",
		},
		{
			name: "PortScan (connection)",
			report: map[string]interface{}{
				"ReportClass": "Activity", "ReportType": "PortScan",
				"Date": "2026-06-23T06:55:10Z", "SourceIp": "203.0.113.11", "SourcePort": 54321,
			},
			wantCat: "connection", wantType: "port_scan",
		},
		{
			name: "LoginAttack (connection)",
			report: map[string]interface{}{
				"ReportClass": "Activity", "ReportType": "LoginAttack",
				"Date": "2026-06-23T06:55:10Z", "SourceIp": "203.0.113.12", "SourcePort": 22,
			},
			wantCat: "connection", wantType: "login_attack",
		},
		{
			name: "Spam (messaging)",
			report: map[string]interface{}{
				"ReportClass": "Activity", "ReportType": "Spam",
				"Date": "2026-06-23T06:55:10Z", "SourceIp": "203.0.113.13", "SourcePort": 587,
				"SmtpMailFromAddress": "spammer@bad.example",
				"SmtpRcptToAddress":   "victim@good.example",
			},
			wantCat: "messaging", wantType: "spam",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseV3(t, mkV3(tc.report))
			if len(res.Errors) != 0 {
				t.Fatalf("expected ACCEPT, got errors: %v", res.Errors)
			}
			if got := res.Report["category"]; got != tc.wantCat {
				t.Errorf("category = %v, want %v", got, tc.wantCat)
			}
			if got := res.Report["type"]; got != tc.wantType {
				t.Errorf("type = %v, want %v", got, tc.wantType)
			}
		})
	}
}

// TestV3RealTraffic_Netcraft is the exact production Netcraft v3 Content/Phishing
// payload that the unpatched converter rejected ("missing URL for content type").
func TestV3RealTraffic_Netcraft(t *testing.T) {
	const b64 = "eyJWZXJzaW9uIjoiMyIsIkRpc2Nsb3N1cmUiOnRydWUsIlJlcG9ydGVySW5mbyI6eyJSZXBvcnRlck9yZyI6IkVudGl0eSBub3QgcHJvdmlkZWQiLCJSZXBvcnRlck9yZ0RvbWFpbiI6ImVudGl0eWRvbWFpbi1ub3Rwcm92aWRlZC5jb20iLCJSZXBvcnRlck9yZ0VtYWlsIjoidGFrZWRvd24tcmVzcG9uc2UrODcwMDk4NjRAbmV0Y3JhZnQuY29tIiwiUmVwb3J0ZXJDb250YWN0RW1haWwiOiJ0YWtlZG93bi1yZXNwb25zZSs4NzAwOTg2NEBuZXRjcmFmdC5jb20iLCJSZXBvcnRlckNvbnRhY3ROYW1lIjoiTmV0Y3JhZnQgUmVwb3J0ZXIifSwiUmVwb3J0Ijp7IlJlcG9ydENsYXNzIjoiQ29udGVudCIsIlJlcG9ydFR5cGUiOiJQaGlzaGluZyIsIkRhdGUiOiIyMDI2LTA2LTIzVDA2OjU1OjEwWiIsIlNvdXJjZUlwIjoiNDUuNzkuMTcxLjY2IiwiU2FtcGxlcyI6W3siQ29udGVudFR5cGUiOiJ0ZXh0L3BsYWluIiwiQmFzZTY0RW5jb2RlZCI6ZmFsc2UsIkRlc2NyaXB0aW9uIjoiRXZpZGVuY2UvTG9ncyIsIlBheWxvYWQiOiJObyBldmlkZW5jZSBsb2dzIHByb3ZpZGVkIn1dLCJTb3VyY2VVcmwiOiJodHRwczovL3JpYm9ybmV4Y2x1c2l2ZS5jb20vd3AtY29udGVudC91cGxvYWRzLzIwMjUvMDMvT29DR1BBRkdKNEdNZ1lJQnhCRkdFRFNBUW8xTWpJek5UTnFNR28zcUFJSHNBSUI4UVUtUzU0LnBocC8iLCJGaWxlU2l6ZSI6MH19"
	body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	res := parseV3(t, body)
	if len(res.Errors) != 0 {
		t.Fatalf("expected Netcraft phishing to ACCEPT, got errors: %v", res.Errors)
	}
	if res.Report["category"] != "content" || res.Report["type"] != "phishing" {
		t.Errorf("got %v/%v, want content/phishing", res.Report["category"], res.Report["type"])
	}
	// SourceUrl must become both the v4 url and the source_identifier.
	const wantURL = "https://ribornexclusive.com/wp-content/uploads/2025/03/OoCGPAFGJ4GMgYIBxBFGEDSAQo1MjIzNTNqMGo3qAIHsAIB8QU-S54.php/"
	if res.Report["url"] != wantURL {
		t.Errorf("url = %v, want %v", res.Report["url"], wantURL)
	}
	if res.Report["source_identifier"] != "45.79.171.66" && res.Report["source_identifier"] != wantURL {
		t.Errorf("source_identifier = %v, want the IP or the URL", res.Report["source_identifier"])
	}
}

// TestV3RealTraffic_EvidenceSamples pins the data-loss fix: v3 Samples evidence
// must be carried into v4 from the schema field `Payload` (not `Data`), honoring
// `Base64Encoded`, with the v4 payload base64-encoded and size/hash over the raw bytes.
func TestV3RealTraffic_EvidenceSamples(t *testing.T) {
	const rawText = "Received: from evil.example\r\nSubject: phish"
	res := parseV3(t, mkV3(map[string]interface{}{
		"ReportClass": "Content", "ReportType": "Phishing",
		"Date": "2026-06-23T06:55:10Z", "SourceUrl": "https://bad.example/login.php",
		"Samples": []interface{}{
			map[string]interface{}{
				"ContentType":   "message/rfc822",
				"Base64Encoded": false,
				"Description":   "Original phishing email",
				"Payload":       rawText,
			},
		},
	}))
	if len(res.Errors) != 0 {
		t.Fatalf("expected ACCEPT, got errors: %v", res.Errors)
	}
	ev, ok := res.Report["evidence"].([]interface{})
	if !ok || len(ev) != 1 {
		t.Fatalf("expected 1 evidence item, got %#v", res.Report["evidence"])
	}
	item := ev[0].(map[string]interface{})
	if item["content_type"] != "message/rfc822" {
		t.Errorf("content_type = %v", item["content_type"])
	}
	if item["description"] != "Original phishing email" {
		t.Errorf("description = %v", item["description"])
	}
	// payload must be the base64 of the raw text (NOT the literal text, NOT empty).
	gotPayload, _ := item["payload"].(string)
	if want := base64.StdEncoding.EncodeToString([]byte(rawText)); gotPayload != want {
		t.Errorf("payload = %q, want base64 %q", gotPayload, want)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotPayload)
	if err != nil || string(decoded) != rawText {
		t.Errorf("payload does not round-trip to the original sample bytes")
	}
	// size is over the raw bytes, not the empty string. Parse returns the
	// in-memory converted map, so numbers stay Go ints (not JSON float64).
	if size := asInt(item["size"]); size != len(rawText) {
		t.Errorf("size = %v, want %d", item["size"], len(rawText))
	}
}

// asInt coerces a JSON number (int or float64) to int for test assertions.
func asInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return -1
	}
}

// TestV3RealTraffic_Copyright pins Copyright as convertible: SourceUrl must map to
// the v4 copyright/copyright required field `infringing_url`.
func TestV3RealTraffic_Copyright(t *testing.T) {
	res := parseV3(t, mkV3(map[string]interface{}{
		"ReportClass": "Content", "ReportType": "Copyright",
		"Date":              "2026-06-23T06:55:10Z",
		"SourceUrl":         "https://pirate.example/movie.mkv",
		"InfringedMaterial": "Some Film (2026)",
	}))
	if len(res.Errors) != 0 {
		t.Fatalf("expected Copyright to ACCEPT, got errors: %v", res.Errors)
	}
	if res.Report["category"] != "copyright" || res.Report["type"] != "copyright" {
		t.Fatalf("got %v/%v, want copyright/copyright", res.Report["category"], res.Report["type"])
	}
	if res.Report["infringing_url"] != "https://pirate.example/movie.mkv" {
		t.Errorf("infringing_url = %v", res.Report["infringing_url"])
	}
}

// TestV3RealTraffic_DescriptionFromReporterNotes pins description sourcing from the
// schema field ReporterNotes (the converter previously read a non-existent field).
func TestV3RealTraffic_DescriptionFromReporterNotes(t *testing.T) {
	res := parseV3(t, mkV3(map[string]interface{}{
		"ReportClass": "Content", "ReportType": "Phishing",
		"Date": "2026-06-23T06:55:10Z", "SourceUrl": "https://bad.example/x",
		"ReporterNotes": "Credential-harvesting page impersonating Acme Bank",
	}))
	if len(res.Errors) != 0 {
		t.Fatalf("expected ACCEPT, got errors: %v", res.Errors)
	}
	if res.Report["description"] != "Credential-harvesting page impersonating Acme Bank" {
		t.Errorf("description = %v", res.Report["description"])
	}
}

// TestV3RealTraffic_DeferredTypesStillRejected documents the v3 ReportTypes that
// are NOT yet convertible (no clean v4.2.0 target, or v4 type requires fields the
// converter cannot supply from v3 data). They must fail clearly, not silently.
func TestV3RealTraffic_DeferredTypesStillRejected(t *testing.T) {
	for _, rt := range []string{"Harassment", "Exploit", "WebCrawler", "PotentiallyCompromisedAccount"} {
		t.Run(rt, func(t *testing.T) {
			res := parseV3(t, mkV3(map[string]interface{}{
				"ReportClass": "Content", "ReportType": rt,
				"Date": "2026-06-23T06:55:10Z", "SourceUrl": "https://x.example/",
			}))
			if len(res.Errors) == 0 {
				t.Fatalf("expected %s to be rejected (not yet supported), but it was accepted", rt)
			}
		})
	}
}
