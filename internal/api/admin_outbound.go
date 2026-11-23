// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/internal/store"
)

func (s *AdminServer) domain(ctx context.Context, tenantID, domainID int64) (store.Domain, error) {
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
	return store.Domain{}, connect.NewError(connect.CodeNotFound, store.ErrNotFound)
}

func (s *AdminServer) GetDomainSetup(ctx context.Context, req *connect.Request[talariav1.GetDomainSetupRequest]) (*connect.Response[talariav1.GetDomainSetupResponse], error) {
	d, err := s.domain(ctx, req.Msg.TenantId, req.Msg.DomainId)
	if err != nil {
		return nil, err
	}
	sel, dkimValue, err := s.Keys.DNSRecord(ctx, d.Name)
	if err != nil {
		return nil, internal(err)
	}
	host := s.Hostname
	spf := "v=spf1 mx ~all"
	spfWhy := "Allows this server to send for the domain."
	if s.RelayHost != "" {
		spfWhy += " Mail leaves through " + s.RelayHost + ": add that provider's include (for example include:_spf.your-relay.example) before ~all."
	}
	recs := []*talariav1.DNSRecord{
		{Type: "MX", Name: d.Name, Value: "10 " + host + ".", Purpose: "Routes incoming mail for the domain to this server."},
		{Type: "TXT", Name: d.Name, Value: spf, Purpose: spfWhy},
		{Type: "TXT", Name: sel + "._domainkey." + d.Name, Value: dkimValue, Purpose: "Publishes the DKIM key that signs outgoing mail."},
		{Type: "TXT", Name: "_dmarc." + d.Name, Value: "v=DMARC1; p=quarantine; adkim=r; aspf=r; rua=mailto:postmaster@" + d.Name,
			Purpose: "Tells receivers to quarantine mail that fails SPF and DKIM, and where to send reports."},
		{Type: "SRV", Name: "_submission._tcp." + d.Name, Value: "0 1 587 " + host + ".", Purpose: "Lets mail apps find the sending server."},
		{Type: "SRV", Name: "_imaps._tcp." + d.Name, Value: "0 1 993 " + host + ".", Purpose: "Lets mail apps find the IMAP server."},
	}
	if req.Msg.Check {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		for _, r := range recs {
			r.Found, r.Ok = checkRecord(cctx, r)
		}
	}
	return connect.NewResponse(&talariav1.GetDomainSetupResponse{Records: recs}), nil
}

func checkRecord(ctx context.Context, r *talariav1.DNSRecord) (string, bool) {
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

func (s *AdminServer) RotateDKIM(ctx context.Context, req *connect.Request[talariav1.RotateDKIMRequest]) (*connect.Response[talariav1.RotateDKIMResponse], error) {
	d, err := s.domain(ctx, req.Msg.TenantId, req.Msg.DomainId)
	if err != nil {
		return nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, internal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	// A second-resolution selector so two rotations in a month differ.
	sel := "tal" + time.Now().UTC().Format("20060102150405")
	if err := s.Store.SetDKIMKey(ctx, store.DKIMKey{DomainID: d.ID, Selector: sel, Algorithm: "rsa", PrivateKey: der}); err != nil {
		return nil, storeErr(err)
	}
	sel, value, err := s.Keys.DNSRecord(ctx, d.Name)
	if err != nil {
		return nil, internal(err)
	}
	return connect.NewResponse(&talariav1.RotateDKIMResponse{Record: &talariav1.DNSRecord{Type: "TXT", Name: sel + "._domainkey." + d.Name, Value: value,
		Purpose: "Publish this record, then wait for DNS to update before mail signed with the new key goes out. Keep the old record for a few days."}}), nil
}

var queueStatus = map[int]talariav1.QueueStatus{
	store.QueueWaiting: talariav1.QueueStatus_QUEUE_STATUS_WAITING,
	store.QueueSending: talariav1.QueueStatus_QUEUE_STATUS_SENDING,
	store.QueueSent:    talariav1.QueueStatus_QUEUE_STATUS_SENT,
	store.QueueBounced: talariav1.QueueStatus_QUEUE_STATUS_BOUNCED,
}

func (s *AdminServer) ListQueue(ctx context.Context, req *connect.Request[talariav1.ListQueueRequest]) (*connect.Response[talariav1.ListQueueResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	status := -1
	for k, v := range queueStatus {
		if v == req.Msg.Status {
			status = k
		}
	}
	items, err := s.Store.ListQueue(ctx, tid, status, int(req.Msg.Limit))
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListQueueResponse{Route: s.Route}
	res.Waiting, res.SentToday, res.BouncedToday, err = s.Store.QueueStats(ctx, tid)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, it := range items {
		res.Items = append(res.Items, &talariav1.QueueItem{Id: it.ID, From: it.MailFrom, To: it.RcptTo, Status: queueStatus[it.Status], Attempts: int32(it.Attempts),
			NextAttempt: it.NextAttempt, LastError: it.LastError, Size: it.Size, CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt})
	}
	return connect.NewResponse(res), nil
}

func (s *AdminServer) RetryQueue(ctx context.Context, req *connect.Request[talariav1.RetryQueueRequest]) (*connect.Response[talariav1.RetryQueueResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := s.Store.RetryNow(ctx, tid, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	if s.Wake != nil {
		s.Wake()
	}
	return connect.NewResponse(&talariav1.RetryQueueResponse{}), nil
}

func (s *AdminServer) CancelQueue(ctx context.Context, req *connect.Request[talariav1.CancelQueueRequest]) (*connect.Response[talariav1.CancelQueueResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := s.Store.CancelQueued(ctx, tid, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.CancelQueueResponse{}), nil
}
