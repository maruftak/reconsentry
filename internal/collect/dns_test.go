package collect

import (
	"context"
	"net"
	"testing"
)

type fakeDNS struct {
	cname map[string]string
	ns    map[string][]string
	mx    map[string][]*net.MX
	txt   map[string][]string
}

func (f fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return host + ".", nil // net.LookupCNAME returns the host itself when there's no CNAME
}

func (f fakeDNS) LookupNS(_ context.Context, host string) ([]*net.NS, error) {
	vals, ok := f.ns[host]
	if !ok {
		return nil, &net.DNSError{Err: "no NS", Name: host, IsNotFound: true}
	}
	out := make([]*net.NS, 0, len(vals))
	for _, v := range vals {
		out = append(out, &net.NS{Host: v})
	}
	return out, nil
}

func (f fakeDNS) LookupMX(_ context.Context, host string) ([]*net.MX, error) {
	vals, ok := f.mx[host]
	if !ok {
		return nil, &net.DNSError{Err: "no MX", Name: host, IsNotFound: true}
	}
	return vals, nil
}

func (f fakeDNS) LookupTXT(_ context.Context, host string) ([]string, error) {
	vals, ok := f.txt[host]
	if !ok {
		return nil, &net.DNSError{Err: "no TXT", Name: host, IsNotFound: true}
	}
	return vals, nil
}

func TestDNSRecords(t *testing.T) {
	orig := DNSResolver
	t.Cleanup(func() { DNSResolver = orig })
	DNSResolver = fakeDNS{
		cname: map[string]string{"blog.acme.com": "acme.ghost.io."},
		ns:    map[string][]string{"acme.com": {"NS1.example-dns.com.", "ns2.example-dns.com."}},
	}

	got, err := DNSRecords(context.Background(), []string{"blog.acme.com", "acme.com", "plain.acme.com"})
	if err != nil {
		t.Fatal(err)
	}

	// blog has a CNAME; acme.com has two NS; plain has neither.
	want := map[string]bool{
		"blog.acme.com|CNAME|acme.ghost.io": true,
		"acme.com|NS|ns1.example-dns.com":   true,
		"acme.com|NS|ns2.example-dns.com":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("want %d records, got %d: %+v", len(want), len(got), got)
	}
	for _, r := range got {
		key := r.Host + "|" + r.Type + "|" + r.Value
		if !want[key] {
			t.Errorf("unexpected/denormalized record: %q", key)
		}
	}
}

func TestDNSRecordsSkipsSelfCNAME(t *testing.T) {
	orig := DNSResolver
	t.Cleanup(func() { DNSResolver = orig })
	DNSResolver = fakeDNS{} // no CNAMEs -> LookupCNAME returns host itself

	got, err := DNSRecords(context.Background(), []string{"www.acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a host that is its own canonical name should yield no CNAME record, got %+v", got)
	}
}

func TestDNSRecordsMXTXT(t *testing.T) {
	orig := DNSResolver
	t.Cleanup(func() { DNSResolver = orig })
	DNSResolver = fakeDNS{
		mx: map[string][]*net.MX{
			"acme.com": {{Host: "ASPMX.L.GOOGLE.com.", Pref: 1}, {Host: "alt1.aspmx.l.google.com.", Pref: 5}},
		},
		txt: map[string][]string{
			"acme.com":        {"v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"},
			"_dmarc.acme.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"},
		},
	}

	got, err := DNSRecords(context.Background(), []string{"acme.com"})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		// MX hosts are normalized (lowercased, trailing dot stripped); preference dropped.
		"acme.com|MX|aspmx.l.google.com":      true,
		"acme.com|MX|alt1.aspmx.l.google.com": true,
		// TXT values are preserved verbatim (only outer whitespace trimmed).
		"acme.com|TXT|v=spf1 include:_spf.google.com ~all": true,
		"acme.com|TXT|google-site-verification=abc":        true,
		// DMARC is collected under the _dmarc.<host> name so posture can be diffed.
		"_dmarc.acme.com|TXT|v=DMARC1; p=reject; rua=mailto:dmarc@acme.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("want %d records, got %d: %+v", len(want), len(got), got)
	}
	for _, r := range got {
		key := r.Host + "|" + r.Type + "|" + r.Value
		if !want[key] {
			t.Errorf("unexpected/denormalized record: %q", key)
		}
	}
}

func TestDNSRecordsNoMXTXTYieldsNothing(t *testing.T) {
	orig := DNSResolver
	t.Cleanup(func() { DNSResolver = orig })
	DNSResolver = fakeDNS{} // no MX, no TXT, no CNAME, no NS

	got, err := DNSRecords(context.Background(), []string{"plain.acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a plain A-record host must yield no MX/TXT records, got %+v", got)
	}
}
