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

func TestDiffDNSMX(t *testing.T) {
	mx := func(h, v string) model.DNSRecord { return model.DNSRecord{Host: h, Type: "MX", Value: v} }

	t.Run("mx swap is a Medium MX_CHANGE", func(t *testing.T) {
		got := DiffDNS(
			[]model.DNSRecord{mx("acme.com", "aspmx.l.google.com")},
			[]model.DNSRecord{mx("acme.com", "mx.sendgrid.net")},
		)
		if len(got) != 1 {
			t.Fatalf("want 1 change, got %d: %+v", len(got), got)
		}
		if got[0].Kind != MXChange || got[0].Priority != Medium {
			t.Errorf("want MX_CHANGE/Medium, got %s/%d", got[0].Kind, got[0].Priority)
		}
		if got[0].Detail != "MX aspmx.l.google.com → mx.sendgrid.net" {
			t.Errorf("detail: got %q", got[0].Detail)
		}
	})

	t.Run("identical mx set yields nothing", func(t *testing.T) {
		recs := []model.DNSRecord{mx("acme.com", "a.mx"), mx("acme.com", "b.mx")}
		if got := DiffDNS(recs, recs); len(got) != 0 {
			t.Fatalf("identical MX set should diff to nothing, got %+v", got)
		}
	})
}

func TestDiffDNSTXTSPF(t *testing.T) {
	txt := func(h, v string) model.DNSRecord { return model.DNSRecord{Host: h, Type: "TXT", Value: v} }

	tests := []struct {
		name      string
		prev      []model.DNSRecord
		curr      []model.DNSRecord
		wantPrio  int
		wantEscal bool // detail must flag the weakening
	}{
		{
			name:     "non-spf txt change stays Low",
			prev:     []model.DNSRecord{txt("acme.com", "google-site-verification=old")},
			curr:     []model.DNSRecord{txt("acme.com", "google-site-verification=new")},
			wantPrio: Low,
		},
		{
			name:     "spf strengthening stays Low",
			prev:     []model.DNSRecord{txt("acme.com", "v=spf1 ~all")},
			curr:     []model.DNSRecord{txt("acme.com", "v=spf1 -all")},
			wantPrio: Low,
		},
		{
			name:      "spf weakening -all to ~all escalates to High",
			prev:      []model.DNSRecord{txt("acme.com", "v=spf1 include:_spf.google.com -all")},
			curr:      []model.DNSRecord{txt("acme.com", "v=spf1 include:_spf.google.com ~all")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "spf weakening ~all to ?all escalates to High",
			prev:      []model.DNSRecord{txt("acme.com", "v=spf1 ~all")},
			curr:      []model.DNSRecord{txt("acme.com", "v=spf1 ?all")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "spf weakening to +all escalates to High",
			prev:      []model.DNSRecord{txt("acme.com", "v=spf1 -all")},
			curr:      []model.DNSRecord{txt("acme.com", "v=spf1 +all")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "spf record removed escalates to High",
			prev:      []model.DNSRecord{txt("acme.com", "v=spf1 -all")},
			curr:      []model.DNSRecord{txt("acme.com", "google-site-verification=x")},
			wantPrio:  High,
			wantEscal: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffDNS(tt.prev, tt.curr)
			if len(got) != 1 {
				t.Fatalf("want 1 change, got %d: %+v", len(got), got)
			}
			if got[0].Kind != TXTChange {
				t.Errorf("want TXT_CHANGE, got %s", got[0].Kind)
			}
			if got[0].Priority != tt.wantPrio {
				t.Errorf("priority: got %d, want %d (detail %q)", got[0].Priority, tt.wantPrio, got[0].Detail)
			}
			if tt.wantEscal && !strings.Contains(got[0].Detail, "SPF weakened") {
				t.Errorf("expected SPF-weakened flag in detail, got %q", got[0].Detail)
			}
		})
	}
}

func TestDiffDNSTXTDMARC(t *testing.T) {
	dmarc := func(v string) model.DNSRecord { return model.DNSRecord{Host: "_dmarc.acme.com", Type: "TXT", Value: v} }

	tests := []struct {
		name      string
		prev      []model.DNSRecord
		curr      []model.DNSRecord
		wantPrio  int
		wantEscal bool
	}{
		{
			name:      "policy reject to none escalates to High",
			prev:      []model.DNSRecord{dmarc("v=DMARC1; p=reject; rua=mailto:x@acme.com")},
			curr:      []model.DNSRecord{dmarc("v=DMARC1; p=none; rua=mailto:x@acme.com")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "policy reject to quarantine escalates to High",
			prev:      []model.DNSRecord{dmarc("v=DMARC1; p=reject")},
			curr:      []model.DNSRecord{dmarc("v=DMARC1; p=quarantine")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "policy quarantine to none escalates to High",
			prev:      []model.DNSRecord{dmarc("v=DMARC1; p=quarantine")},
			curr:      []model.DNSRecord{dmarc("v=DMARC1; p=none")},
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:      "dmarc record removed escalates to High",
			prev:      []model.DNSRecord{dmarc("v=DMARC1; p=reject")},
			curr:      nil,
			wantPrio:  High,
			wantEscal: true,
		},
		{
			name:     "policy none to reject (strengthening) stays Low",
			prev:     []model.DNSRecord{dmarc("v=DMARC1; p=none")},
			curr:     []model.DNSRecord{dmarc("v=DMARC1; p=reject")},
			wantPrio: Low,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffDNS(tt.prev, tt.curr)
			if len(got) != 1 {
				t.Fatalf("want 1 change, got %d: %+v", len(got), got)
			}
			if got[0].Kind != TXTChange {
				t.Errorf("want TXT_CHANGE, got %s", got[0].Kind)
			}
			if got[0].Priority != tt.wantPrio {
				t.Errorf("priority: got %d, want %d (detail %q)", got[0].Priority, tt.wantPrio, got[0].Detail)
			}
			if tt.wantEscal && !strings.Contains(got[0].Detail, "DMARC weakened") {
				t.Errorf("expected DMARC-weakened flag in detail, got %q", got[0].Detail)
			}
		})
	}
}
