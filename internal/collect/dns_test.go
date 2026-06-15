package collect

import (
	"context"
	"net"
	"testing"
)

type fakeDNS struct {
	cname map[string]string
	ns    map[string][]string
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
