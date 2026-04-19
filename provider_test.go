// Package dinahosting implements a DNS record management client compatible
// with the libdns interfaces for Dinahosting (https://es.dinahosting.com/api).
package dinahosting

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// To be able to run the tests successfully please replace these constants
// with your actual account details. Leaving password empty makes the live
// integration tests skip, so CI and third parties can still run
// `go test ./...` without credentials.
//
// The zone is expected to exist but doesn't need to contain any specific
// records: each test creates and deletes its own fixtures.
const (
	username = "username"
	password = "password"
	zone     = "example.com"
)

// skipIfNoCredentials lets the test suite be runnable in CI or by third
// parties without credentials while still being usable as an end-to-end
// smoke test by maintainers.
func skipIfNoCredentials(t *testing.T) {
	t.Helper()
	if password == "" || password == "YOUR_PASSWORD" {
		t.Skip("Dinahosting credentials not configured; set the `password` constant in provider_test.go to run live tests.")
	}
}

// bestEffortDelete deletes the given records ignoring any error. Used as a
// cleanup hook so tests are idempotent: the Dinahosting provider already
// silently ignores records that don't exist, so calling this is safe
// regardless of whether the record was actually created.
func bestEffortDelete(t *testing.T, p *Provider, recs ...libdns.Record) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := p.DeleteRecords(ctx, zone, recs); err != nil {
		t.Logf("bestEffortDelete: %v", err)
	}
}

// rrSlice converts a slice of libdns.Record into their underlying RR so they
// can be compared reliably regardless of the concrete struct type.
func rrSlice(records []libdns.Record) []libdns.RR {
	out := make([]libdns.RR, len(records))
	for i, r := range records {
		out[i] = r.RR()
	}
	return out
}

// newProvider returns a configured provider for the live integration tests.
func newProvider() *Provider {
	return &Provider{Username: username, Password: password}
}

// TestProvider_GetRecords verifies that the zone can be read, that a freshly
// created record is returned with the expected concrete type, and that
// invalid credentials cause an error.
func TestProvider_GetRecords(t *testing.T) {
	skipIfNoCredentials(t)

	p := newProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fixture := libdns.Address{Name: "get-test", IP: netip.MustParseAddr("203.0.113.10")}
	bestEffortDelete(t, p, fixture)
	t.Cleanup(func() { bestEffortDelete(t, p, fixture) })

	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{fixture}); err != nil {
		t.Fatalf("setup AppendRecords() error: %v", err)
	}

	t.Run("Reads freshly created A record", func(t *testing.T) {
		got, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatalf("GetRecords() unexpected error: %v", err)
		}

		var found bool
		for _, rec := range got {
			addr, ok := rec.(libdns.Address)
			if !ok {
				continue
			}
			if addr.Name == fixture.Name && addr.IP == fixture.IP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetRecords() did not return expected A record %s -> %s; got: %+v", fixture.Name, fixture.IP, rrSlice(got))
		}
	})

	t.Run("Returns error with wrong credentials", func(t *testing.T) {
		bad := &Provider{Username: "wrongUser", Password: "wrongPass"}
		got, err := bad.GetRecords(ctx, zone)
		if err == nil {
			t.Errorf("GetRecords() expected error with wrong credentials, got records: %+v", got)
		}
	})
}

// TestProvider_AppendRecords creates A, AAAA, TXT and CNAME records one by
// one, checks the returned concrete types, and verifies that duplicates are
// rejected. Each subtest registers its own cleanup so the suite is
// idempotent.
func TestProvider_AppendRecords(t *testing.T) {
	skipIfNoCredentials(t)

	p := newProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cases := []struct {
		name string
		rec  libdns.Record
	}{
		{"A", libdns.Address{Name: "append-a", IP: netip.MustParseAddr("203.0.113.11")}},
		{"AAAA", libdns.Address{Name: "append-aaaa", IP: netip.MustParseAddr("2001:db8::11")}},
		{"TXT", libdns.TXT{Name: "append-txt", Text: "libdns-dinahosting-test"}},
		{"CNAME", libdns.CNAME{Name: "append-cname", Target: "dinahosting.com"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("Create "+tc.name+" record", func(t *testing.T) {
			bestEffortDelete(t, p, tc.rec)
			t.Cleanup(func() { bestEffortDelete(t, p, tc.rec) })

			got, err := p.AppendRecords(ctx, zone, []libdns.Record{tc.rec})
			if err != nil {
				t.Fatalf("AppendRecords() unexpected error: %v", err)
			}
			if len(got) != 1 || !reflect.DeepEqual(got[0].RR(), tc.rec.RR()) {
				t.Errorf("AppendRecords() = %+v, want %+v", rrSlice(got), []libdns.RR{tc.rec.RR()})
			}
		})
	}

	t.Run("Error when same A record exists", func(t *testing.T) {
		dup := libdns.Address{Name: "append-dup", IP: netip.MustParseAddr("203.0.113.12")}
		bestEffortDelete(t, p, dup)
		t.Cleanup(func() { bestEffortDelete(t, p, dup) })

		if _, err := p.AppendRecords(ctx, zone, []libdns.Record{dup}); err != nil {
			t.Fatalf("setup AppendRecords() error: %v", err)
		}
		if _, err := p.AppendRecords(ctx, zone, []libdns.Record{dup}); err == nil {
			t.Errorf("AppendRecords() expected error when adding duplicate A record")
		}
	})
}

// TestProvider_SetRecords verifies that SetRecords replaces an existing RRset
// (delete + append) and also creates the record when it doesn't exist.
func TestProvider_SetRecords(t *testing.T) {
	skipIfNoCredentials(t)

	p := newProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	initial := libdns.Address{Name: "set-a", IP: netip.MustParseAddr("203.0.113.21")}
	updated := libdns.Address{Name: "set-a", IP: netip.MustParseAddr("203.0.113.22")}
	created := libdns.TXT{Name: "set-txt", Text: "hello-libdns"}

	bestEffortDelete(t, p, initial, updated, created)
	t.Cleanup(func() { bestEffortDelete(t, p, initial, updated, created) })

	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{initial}); err != nil {
		t.Fatalf("setup AppendRecords() error: %v", err)
	}

	t.Run("Updates existing A record", func(t *testing.T) {
		got, err := p.SetRecords(ctx, zone, []libdns.Record{updated})
		if err != nil {
			t.Fatalf("SetRecords() unexpected error: %v", err)
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0].RR(), updated.RR()) {
			t.Errorf("SetRecords() = %+v, want %+v", rrSlice(got), []libdns.RR{updated.RR()})
		}

		// Verify the previous value is gone by listing the zone.
		list, err := p.GetRecords(ctx, zone)
		if err != nil {
			t.Fatalf("GetRecords() unexpected error: %v", err)
		}
		for _, rec := range list {
			addr, ok := rec.(libdns.Address)
			if !ok {
				continue
			}
			if addr.Name == initial.Name && addr.IP == initial.IP {
				t.Errorf("SetRecords() did not remove previous A record %s -> %s", initial.Name, initial.IP)
			}
		}
	})

	t.Run("Creates new TXT record via SetRecords", func(t *testing.T) {
		got, err := p.SetRecords(ctx, zone, []libdns.Record{created})
		if err != nil {
			t.Fatalf("SetRecords() unexpected error: %v", err)
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0].RR(), created.RR()) {
			t.Errorf("SetRecords() = %+v, want %+v", rrSlice(got), []libdns.RR{created.RR()})
		}
	})
}

// TestProvider_DeleteRecords creates records and then removes them. It also
// verifies that deleting records that do not exist is silently ignored, as
// required by the libdns.RecordDeleter semantics.
func TestProvider_DeleteRecords(t *testing.T) {
	skipIfNoCredentials(t)

	p := newProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	records := []libdns.Record{
		libdns.Address{Name: "del-a", IP: netip.MustParseAddr("203.0.113.31")},
		libdns.Address{Name: "del-aaaa", IP: netip.MustParseAddr("2001:db8::31")},
		libdns.TXT{Name: "del-txt", Text: "libdns-dinahosting-test"},
		libdns.CNAME{Name: "del-cname", Target: "dinahosting.com"},
	}

	bestEffortDelete(t, p, records...)
	t.Cleanup(func() { bestEffortDelete(t, p, records...) })

	t.Run("Removes previously created records", func(t *testing.T) {
		if _, err := p.AppendRecords(ctx, zone, records); err != nil {
			t.Fatalf("setup AppendRecords() error: %v", err)
		}

		got, err := p.DeleteRecords(ctx, zone, records)
		if err != nil {
			t.Fatalf("DeleteRecords() unexpected error: %v", err)
		}
		if !reflect.DeepEqual(rrSlice(got), rrSlice(records)) {
			t.Errorf("DeleteRecords() returned %+v, want %+v", rrSlice(got), rrSlice(records))
		}
	})

	t.Run("Silently ignores non-existent records", func(t *testing.T) {
		got, err := p.DeleteRecords(ctx, zone, records)
		if err != nil {
			t.Fatalf("DeleteRecords() unexpected error for non-existent records: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("DeleteRecords() returned %+v records for non-existent input; expected empty", rrSlice(got))
		}
	})
}
