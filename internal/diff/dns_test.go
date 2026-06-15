package diff

import (
	"strings"
	"testing"

	"github.com/maruftak/reconsentry/internal/model"
)

func TestDiffDNS(t *testing.T) {
	cname := func(h, v string) model.DNSRecord { return model.DNSRecord{Host: h, Type: "CNAME", Value: v} }
	ns := func(h, v string) model.DNSRecord { return model.DNSRecord{Host: h, Type: "NS", Value: v} }

	t.Run("no change yields nothing", func(t *testing.T) {
		recs := []model.DNSRecord{cname("a.x", "old.svc"), ns("x", "ns1")}
		if got := DiffDNS(recs, recs); len(got) != 0 {
			t.Fatalf("identical sets should diff to nothing, got %+v", got)
		}
	})

	t.Run("cname swap is one Medium change with arrow detail", func(t *testing.T) {
		got := DiffDNS([]model.DNSRecord{cname("a.x", "old.svc")}, []model.DNSRecord{cname("a.x", "new.svc")})
		if len(got) != 1 {
			t.Fatalf("want 1 change, got %d: %+v", len(got), got)
		}
		if got[0].Kind != DNSChange || got[0].Priority != Medium {
			t.Errorf("want DNS_CHANGE/Medium, got %s/%d", got[0].Kind, got[0].Priority)
		}
		if got[0].Detail != "CNAME old.svc → new.svc" {
			t.Errorf("detail: got %q", got[0].Detail)
		}
	})

	t.Run("ns change is High and lists added/removed", func(t *testing.T) {
		got := DiffDNS(
			[]model.DNSRecord{ns("x", "ns1.dns")},
			[]model.DNSRecord{ns("x", "ns1.dns"), ns("x", "ns2.dns"), ns("x", "ns3.dns")},
		)
		if len(got) != 1 {
			t.Fatalf("want 1 change, got %d: %+v", len(got), got)
		}
		if got[0].Priority != High {
			t.Errorf("NS change should be High, got %d", got[0].Priority)
		}
		if !strings.Contains(got[0].Detail, "+ns2.dns") || !strings.Contains(got[0].Detail, "+ns3.dns") {
			t.Errorf("detail should list added nameservers, got %q", got[0].Detail)
		}
	})

	t.Run("brand-new record", func(t *testing.T) {
		got := DiffDNS(nil, []model.DNSRecord{cname("a.x", "svc")})
		if len(got) != 1 || got[0].Detail != "CNAME +svc" {
			t.Fatalf("want one '+svc' change, got %+v", got)
		}
	})
}
