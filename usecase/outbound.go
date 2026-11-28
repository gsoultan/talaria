// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"time"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/store"
)

func (s *Admin) domain(ctx context.Context, tenantID, domainID int64) (store.Domain, error) {
	_, tid, err := scope(ctx, tenantID)
	if err != nil {
		return store.Domain{}, err
	}
	ds, err := s.Store.ListDomains(ctx, tid)
	if err != nil {
		return store.Domain{}, storeErr(err)
	}
	for _, d := range ds {
		if d.ID == domainID {
			return d, nil
		}
	}
	return store.Domain{}, kakarot.NotFound("domain", fmt.Sprint(domainID))
}

// GetDomainSetup lists the DNS records a domain needs and, with Check,
// what DNS has now.
func (s *Admin) GetDomainSetup(ctx context.Context, in domain.GetDomainSetup) (domain.DomainSetup, error) {
	d, err := s.domain(ctx, in.TenantID, in.DomainID)
	if err != nil {
		return domain.DomainSetup{}, err
	}
	sel, dkimValue, err := s.Keys.DNSRecord(ctx, d.Name)
	if err != nil {
		return domain.DomainSetup{}, internal(err)
	}
	host := s.Hostname
	spfWhy := "Allows this server to send for the domain."
	if s.RelayHost != "" {
		spfWhy += " Mail leaves through " + s.RelayHost + ": add that provider's include (for example include:_spf.your-relay.example) before ~all."
	}
	recs := []domain.DNSRecord{
		{Type: "MX", Name: d.Name, Value: "10 " + host + ".", Purpose: "Routes incoming mail for the domain to this server."},
		{Type: "TXT", Name: d.Name, Value: "v=spf1 mx ~all", Purpose: spfWhy},
		{Type: "TXT", Name: sel + "._domainkey." + d.Name, Value: dkimValue, Purpose: "Publishes the DKIM key that signs outgoing mail."},
		{Type: "TXT", Name: "_dmarc." + d.Name, Value: "v=DMARC1; p=quarantine; adkim=r; aspf=r; rua=mailto:postmaster@" + d.Name,
			Purpose: "Tells receivers to quarantine mail that fails SPF and DKIM, and where to send reports."},
		{Type: "SRV", Name: "_submission._tcp." + d.Name, Value: "0 1 587 " + host + ".", Purpose: "Lets mail apps find the sending server."},
		{Type: "SRV", Name: "_imaps._tcp." + d.Name, Value: "0 1 993 " + host + ".", Purpose: "Lets mail apps find the IMAP server."},
	}
	if in.Check {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		for i := range recs {
			recs[i].Found, recs[i].OK = checkRecord(cctx, recs[i])
		}
	}
	return domain.DomainSetup{Records: recs}, nil
}

func checkRecord(ctx context.Context, r domain.DNSRecord) (string, bool) {
	res := net.DefaultResolver
	norm := func(s string) string {
		return strings.ToLower(strings.Join(strings.Fields(strings.TrimSuffix(s, ".")), " "))
	}
	switch r.Type {
	case "MX":
		mxs, err := res.LookupMX(ctx, r.Name)
		if err != nil {
			return "", false
		}
		var found []string
		want := norm(strings.SplitN(r.Value, " ", 2)[1])
		ok := false
		for _, mx := range mxs {
			found = append(found, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
			ok = ok || norm(mx.Host) == want
		}
		return strings.Join(found, ", "), ok
	case "TXT":
		txts, err := res.LookupTXT(ctx, r.Name)
		if err != nil {
			return "", false
		}
		prefix := strings.SplitN(r.Value, ";", 2)[0]
		if strings.HasPrefix(r.Value, "v=spf1") {
			prefix = "v=spf1"
		}
		for _, t := range txts {
			if !strings.HasPrefix(t, prefix) {
				continue
			}
			if strings.HasPrefix(r.Value, "v=DKIM1") {
				return t, norm(t) == norm(r.Value)
			}
			return t, true // SPF and DMARC policies are the owner's to tune
		}
		return strings.Join(txts, " | "), false
	case "SRV":
		parts := strings.SplitN(r.Name, ".", 3)
		_, srvs, err := res.LookupSRV(ctx, strings.TrimPrefix(parts[0], "_"), strings.TrimPrefix(parts[1], "_"), parts[2])
		if err != nil {
			return "", false
		}
		want := strings.Fields(r.Value)
		for _, s := range srvs {
			if fmt.Sprint(s.Port) == want[2] && norm(s.Target) == norm(want[3]) {
				return fmt.Sprintf("%d %d %d %s", s.Priority, s.Weight, s.Port, s.Target), true
			}
		}
		return "", false
	}
	return "", false
}

// RotateDKIM makes a new DKIM key and returns the record to publish.
func (s *Admin) RotateDKIM(ctx context.Context, in domain.RotateDKIM) (domain.DKIMRotated, error) {
	d, err := s.domain(ctx, in.TenantID, in.DomainID)
	if err != nil {
		return domain.DKIMRotated{}, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return domain.DKIMRotated{}, internal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	// A second-resolution selector so two rotations in a month differ.
	sel := "tal" + time.Now().UTC().Format("20060102150405")
	if err := s.Store.SetDKIMKey(ctx, store.DKIMKey{DomainID: d.ID, Selector: sel, Algorithm: "rsa", PrivateKey: der}); err != nil {
		return domain.DKIMRotated{}, storeErr(err)
	}
	sel, value, err := s.Keys.DNSRecord(ctx, d.Name)
	if err != nil {
		return domain.DKIMRotated{}, internal(err)
	}
	return domain.DKIMRotated{Record: domain.DNSRecord{Type: "TXT", Name: sel + "._domainkey." + d.Name, Value: value,
		Purpose: "Publish this record, then wait for DNS to update before mail signed with the new key goes out. Keep the old record for a few days."}}, nil
}

var queueStatus = map[int]domain.QueueStatus{
	store.QueueWaiting: domain.QueueWaiting,
	store.QueueSending: domain.QueueSending,
	store.QueueSent:    domain.QueueSent,
	store.QueueBounced: domain.QueueBounced,
}

// ListQueue returns outgoing mail.
func (s *Admin) ListQueue(ctx context.Context, in domain.ListQueue) (domain.Queue, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Queue{}, err
	}
	status := -1
	for k, v := range queueStatus {
		if v == in.Status {
			status = k
		}
	}
	if in.Status != "" && status < 0 {
		return domain.Queue{}, kakarot.Invalid("unknown status", map[string]string{"status": "use waiting, sending, sent or bounced"})
	}
	items, err := s.Store.ListQueue(ctx, tid, status, in.Limit)
	if err != nil {
		return domain.Queue{}, storeErr(err)
	}
	out := domain.Queue{Route: s.Route, Items: make([]domain.QueueItem, len(items))}
	out.Waiting, out.SentToday, out.BouncedToday, err = s.Store.QueueStats(ctx, tid)
	if err != nil {
		return domain.Queue{}, storeErr(err)
	}
	for i, it := range items {
		out.Items[i] = domain.QueueItem{ID: it.ID, From: it.MailFrom, To: it.RcptTo, Status: queueStatus[it.Status], Attempts: it.Attempts,
			NextAttempt: it.NextAttempt, LastError: it.LastError, Size: it.Size, CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt}
	}
	return out, nil
}

// RetryQueue tries waiting mail now.
func (s *Admin) RetryQueue(ctx context.Context, in domain.RetryQueue) (domain.Done, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	if err := s.Store.RetryNow(ctx, tid, in.ID); err != nil {
		return domain.Done{}, storeErr(err)
	}
	if s.Wake != nil {
		s.Wake()
	}
	return domain.Done{}, nil
}

// CancelQueue stops trying a message.
func (s *Admin) CancelQueue(ctx context.Context, in domain.CancelQueue) (domain.Done, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.CancelQueued(ctx, tid, in.ID))
}

var started = time.Now()

func heapBytes() int64 {
	// runtime/metrics is cheap; ReadMemStats would stop the world.
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindUint64 {
		return int64(sample[0].Value.Uint64())
	}
	return 0
}

// GetStats returns the dashboard numbers for a tenant or the server.
func (s *Admin) GetStats(ctx context.Context, in domain.GetStats) (domain.Stats, error) {
	var tenantID int64
	if in.Server {
		if err := platform(ctx); err != nil {
			return domain.Stats{}, err
		}
	} else {
		_, t, err := scope(ctx, in.TenantID)
		if err != nil {
			return domain.Stats{}, err
		}
		tenantID = t
	}
	st, err := s.Store.Stats(ctx, tenantID)
	if err != nil {
		return domain.Stats{}, internal(err)
	}
	waiting, sent, bounced, err := s.Store.QueueStats(ctx, tenantID)
	if err != nil {
		return domain.Stats{}, internal(err)
	}
	out := domain.Stats{
		Tenants: st.Tenants, Domains: st.Domains, Users: st.Users, UsedBytes: st.UsedBytes,
		StoredBytes: st.StoredBytes, RawBytes: st.RawBytes, ReceivedToday: st.ReceivedToday, JunkToday: st.JunkToday,
		QueueWaiting: waiting, SentToday: sent, BouncedToday: bounced, Route: s.Route,
	}
	if in.Server {
		out.HeapBytes = heapBytes()
		out.MemoryLimitBytes = debug.SetMemoryLimit(-1)
		out.UptimeSeconds = int64(time.Since(started).Seconds())
	} else if t, err := s.Store.Tenant(ctx, tenantID); err == nil {
		out.SeatLimit, out.QuotaBytes = t.SeatLimit, t.QuotaBytes
	}
	return out, nil
}
