// Package dinahosting implements a DNS record management client compatible
// with the libdns interfaces for Dinahosting (https://es.dinahosting.com/api).
//
// This package supports the following record types for writes (Append, Set,
// Delete): A, AAAA, TXT and CNAME. GetRecords additionally returns any other
// record types present in the zone as opaque [libdns.RR] values.
package dinahosting

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const (
	endpointBase = "https://dinahosting.com/special/api.php"
)

type command string

// API commands used by this provider.
const (
	domain_Zone_GetAll         command = "Domain_Zone_GetAll"
	domain_Zone_AddTypeA       command = "Domain_Zone_AddTypeA"
	domain_Zone_DeleteTypeA    command = "Domain_Zone_DeleteTypeA"
	domain_Zone_AddTypeAAAA    command = "Domain_Zone_AddTypeAAAA"
	domain_Zone_DeleteTypeAAAA command = "Domain_Zone_DeleteTypeAAAA"
	domain_Zone_AddTypeTXT     command = "Domain_Zone_AddTypeTXT"
	domain_Zone_DeleteTypeTXT  command = "Domain_Zone_DeleteTypeTXT"
	domain_Zone_AddTypeCname   command = "Domain_Zone_AddTypeCname"
	domain_Zone_DeleteTypeCname command = "Domain_Zone_DeleteTypeCname"
)

// Provider facilitates DNS record manipulation with Dinahosting.
type Provider struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// HTTPClient, if non-nil, is used to perform requests to the Dinahosting
	// API. When nil, an internal client with a generous per-request timeout
	// is used. Callers that need a custom transport, proxy, TLS config or
	// their own retry/observability layer can inject their own client here.
	HTTPClient *http.Client `json:"-"`
}

// dinaResponse mirrors the relevant portion of a Dinahosting JSON API response.
// Not every field is populated for every command; the API uses different keys
// depending on the record type being returned. On error responses the "data"
// field is replaced by an "errors" array.
type dinaResponse struct {
	TrID         string       `json:"trId,omitempty"`
	ResponseCode int16        `json:"responseCode,omitempty"`
	Message      string       `json:"message,omitempty"`
	Records      []dinaRecord `json:"data,omitempty"`
	Errors       []dinaError  `json:"errors,omitempty"`
	Command      string       `json:"command,omitempty"`
}

type dinaRecord struct {
	RecordType          string `json:"type,omitempty"`
	Hostname            string `json:"hostname,omitempty"`
	Host                string `json:"host,omitempty"`
	DestinationHostname string `json:"destinationHostname,omitempty"`
	DestinationURL      string `json:"destinationUrl,omitempty"`
	IP                  string `json:"ip,omitempty"`
	Address             string `json:"address,omitempty"`
	Text                string `json:"text,omitempty"`
}

type dinaError struct {
	Message   string `json:"message,omitempty"`
	Code      int16  `json:"code,omitempty"`
	Parameter string `json:"parameter,omitempty"`
}

// ok reports whether the response represents a success.
func (r *dinaResponse) ok() bool {
	return r.Message == "Success." || r.ResponseCode == 1000
}

// errString returns a human-readable description of an error response.
func (r *dinaResponse) errString() string {
	if len(r.Errors) > 0 {
		parts := make([]string, 0, len(r.Errors))
		for _, e := range r.Errors {
			parts = append(parts, fmt.Sprintf("code=%d msg=%q", e.Code, e.Message))
		}
		return strings.Join(parts, "; ")
	}
	return fmt.Sprintf("code=%d", r.ResponseCode)
}

// defaultHTTPClient is used when Provider.HTTPClient is nil. The Dinahosting
// API occasionally takes 10+ seconds to respond to zone-related commands,
// specially right after a write operation, so the per-request timeout is
// intentionally generous. Callers that need a different timeout can provide
// their own http.Client.
var defaultHTTPClient = &http.Client{Timeout: 45 * time.Second}

// Retry policy for transient transport/5xx failures. Dinahosting returns
// HTTP 200 with a JSON body for all business-logic errors, so only
// network-level errors and HTTP 5xx are considered retryable.
const (
	maxRetries     = 3
	initialBackoff = time.Second
)

// Dinahosting API response codes relevant to this provider.
const (
	dinaCodeObjectNotExists = 2303
)

// GetRecords lists all the records in the zone.
//
// A and AAAA records are returned as [libdns.Address], TXT as [libdns.TXT],
// CNAME as [libdns.CNAME]. Any other record type is returned as an opaque
// [libdns.RR] so callers can still enumerate what exists in the zone.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	endpoint, err := p.buildQuery(zone, domain_Zone_GetAll)
	if err != nil {
		return nil, err
	}

	response, err := p.doRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	if !response.ok() {
		return nil, fmt.Errorf("could not retrieve records. Dinahosting API error: %s", response.errString())
	}

	records := make([]libdns.Record, 0, len(response.Records))
	for _, r := range response.Records {
		name := r.Hostname
		if name == "" {
			name = r.Host
		}

		switch r.RecordType {
		case "A", "AAAA":
			ip, parseErr := netip.ParseAddr(r.IP)
			if parseErr != nil {
				// Fall back to an opaque RR so the record is still visible.
				records = append(records, libdns.RR{Type: r.RecordType, Name: name, Data: r.IP})
				continue
			}
			records = append(records, libdns.Address{Name: name, IP: ip})
		case "TXT":
			records = append(records, libdns.TXT{Name: name, Text: r.Text})
		case "CNAME":
			records = append(records, libdns.CNAME{Name: name, Target: r.DestinationHostname})
		default:
			data := firstNonEmpty(r.DestinationHostname, r.DestinationURL, r.IP, r.Address, r.Text)
			records = append(records, libdns.RR{Type: r.RecordType, Name: name, Data: data})
		}
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were
// added as concrete libdns RR-type structs (A/AAAA as [libdns.Address], TXT as
// [libdns.TXT], CNAME as [libdns.CNAME]).
//
// Supported record types: A, AAAA, TXT, CNAME.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("empty input Record list")
	}

	results := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rr := record.RR()

		var cmd command
		switch rr.Type {
		case "A":
			cmd = domain_Zone_AddTypeA
		case "AAAA":
			cmd = domain_Zone_AddTypeAAAA
		case "TXT":
			cmd = domain_Zone_AddTypeTXT
		case "CNAME":
			cmd = domain_Zone_AddTypeCname
		default:
			return nil, fmt.Errorf("creating %s records is not supported or not implemented yet", rr.Type)
		}

		endpoint, err := p.buildQueryWithRR(zone, cmd, rr)
		if err != nil {
			return nil, err
		}

		response, err := p.doRequest(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		if !response.ok() {
			return nil, fmt.Errorf("could not create %s record %q. Dinahosting API error: %s", rr.Type, rr.Name, response.errString())
		}

		typed, err := typedRecord(rr)
		if err != nil {
			return nil, err
		}
		results = append(results, typed)
	}

	return results, nil
}

// SetRecords updates the zone so that the RRset formed by each input record's
// (Name, Type) pair contains exactly the input records. It implements the
// canonical semantics described in the godoc of [libdns.RecordSetter]: existing
// records in the same RRset are deleted first, then the new records are
// appended.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("empty input Record list")
	}

	existing, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var toDelete []libdns.Record
	for _, prev := range existing {
		prevRR := prev.RR()
		for _, in := range records {
			inRR := in.RR()
			if prevRR.Name == inRR.Name && prevRR.Type == inRR.Type {
				toDelete = append(toDelete, prev)
				break
			}
		}
	}

	if len(toDelete) > 0 {
		if _, err := p.DeleteRecords(ctx, zone, toDelete); err != nil {
			return nil, err
		}
	}

	return p.AppendRecords(ctx, zone, records)
}

// DeleteRecords deletes the records from the zone. It returns the records that
// were deleted as concrete libdns RR-type structs.
//
// Supported record types: A, AAAA, TXT, CNAME.
//
// API docs: https://es.dinahosting.com/api/documentation
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	results := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rr := record.RR()

		var cmd command
		switch rr.Type {
		case "A":
			cmd = domain_Zone_DeleteTypeA
		case "AAAA":
			cmd = domain_Zone_DeleteTypeAAAA
		case "TXT":
			cmd = domain_Zone_DeleteTypeTXT
		case "CNAME":
			cmd = domain_Zone_DeleteTypeCname
		default:
			return nil, fmt.Errorf("deleting record type %s is not supported or not implemented yet", rr.Type)
		}

		endpoint, err := p.buildQueryWithRR(zone, cmd, rr)
		if err != nil {
			return nil, err
		}

		response, err := p.doRequest(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		if !response.ok() {
			// Per libdns.RecordDeleter semantics, records that don't exist in
			// the zone are silently ignored (i.e. not returned, not errored).
			if response.ResponseCode == dinaCodeObjectNotExists {
				continue
			}
			return nil, fmt.Errorf("deletion of %s record %q failed. Dinahosting API error: %s", rr.Type, rr.Name, response.errString())
		}

		typed, err := typedRecord(rr)
		if err != nil {
			return nil, err
		}
		results = append(results, typed)
	}
	return results, nil
}

// doRequest performs a GET against the Dinahosting endpoint and decodes the
// JSON response. It retries on transient transport-level errors and HTTP 5xx
// responses with exponential backoff, always respecting the caller's context.
//
// Business-logic errors (the API returning HTTP 200 with a non-success
// `responseCode` in the JSON body) are NOT retried: they are deterministic
// and would produce the same result on a retry.
func (p *Provider) doRequest(ctx context.Context, endpoint *url.URL) (*dinaResponse, error) {
	client := p.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}

	url := endpoint.String()
	backoff := initialBackoff
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			// If the caller's context is done, stop retrying: they've given
			// up and any further attempt would waste their deadline.
			if ctx.Err() != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode >= 500 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("Dinahosting API returned HTTP %d", resp.StatusCode)
			if ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}

		parsed, err := decodeResponse(resp)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	}

	return nil, fmt.Errorf("request to Dinahosting failed after %d attempts: %w", maxRetries+1, lastErr)
}

// decodeResponse reads the HTTP response body, discarding any trailing bytes
// so the connection can be reused, and decodes the JSON into a dinaResponse.
func decodeResponse(resp *http.Response) (*dinaResponse, error) {
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	var parsed dinaResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("API response parsing failed (HTTP %d): %w", resp.StatusCode, err)
	}
	return &parsed, nil
}

// buildQuery builds the base endpoint URL with the authentication parameters
// and, when the command is Domain_Zone_GetAll, also includes the command
// parameter. For other commands the caller is expected to append any extra
// parameters (including the command itself) via buildQueryWithRR.
func (p *Provider) buildQuery(zone string, cmd command) (*url.URL, error) {
	endpoint, err := url.Parse(endpointBase)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("AUTH_USER", p.Username)
	params.Add("AUTH_PWD", p.Password)
	params.Add("domain", strings.TrimSuffix(zone, "."))
	params.Add("responseType", "json")

	if cmd == domain_Zone_GetAll {
		params.Add("command", string(domain_Zone_GetAll))
	}

	endpoint.RawQuery = params.Encode()
	return endpoint, nil
}

// buildQueryWithRR builds the full endpoint URL for a command that operates on
// a specific record, mapping the RR fields to the parameter names expected by
// Dinahosting's API for each command.
func (p *Provider) buildQueryWithRR(zone string, cmd command, rr libdns.RR) (*url.URL, error) {
	endpoint, err := p.buildQuery(zone, cmd)
	if err != nil {
		return nil, err
	}
	params := endpoint.Query()
	params.Add("command", string(cmd))

	switch cmd {
	case domain_Zone_AddTypeA, domain_Zone_DeleteTypeA,
		domain_Zone_AddTypeAAAA, domain_Zone_DeleteTypeAAAA:
		params.Add("hostname", rr.Name)
		params.Add("ip", rr.Data)
	case domain_Zone_AddTypeTXT:
		params.Add("hostname", rr.Name)
		params.Add("text", rr.Data)
	case domain_Zone_DeleteTypeTXT:
		params.Add("hostname", rr.Name)
		if rr.Data != "" {
			params.Add("value", rr.Data)
		}
	case domain_Zone_AddTypeCname:
		params.Add("hostname", rr.Name)
		params.Add("destinationHostname", rr.Data)
	case domain_Zone_DeleteTypeCname:
		params.Add("hostname", rr.Name)
	default:
		return nil, fmt.Errorf("unsupported command: %s", cmd)
	}

	endpoint.RawQuery = params.Encode()
	return endpoint, nil
}

// typedRecord turns an opaque RR into its specific libdns RR-type struct so
// the provider can return values conforming to the libdns v1 recommendation.
func typedRecord(rr libdns.RR) (libdns.Record, error) {
	switch rr.Type {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q for %s record: %w", rr.Data, rr.Type, err)
		}
		return libdns.Address{Name: rr.Name, TTL: rr.TTL, IP: ip}, nil
	case "TXT":
		return libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data}, nil
	case "CNAME":
		return libdns.CNAME{Name: rr.Name, TTL: rr.TTL, Target: rr.Data}, nil
	default:
		return rr, nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
