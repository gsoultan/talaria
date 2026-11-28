// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"
	"strings"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/dlp"
	"github.com/gsoultan/talaria/internal/store"
)

func dlpOf(p store.DLPPolicy) domain.DLPPolicy {
	return domain.DLPPolicy{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Detector: p.Detector, Pattern: p.Pattern, MinCount: p.MinCount,
		Action: domain.DLPAction(p.Action), ExternalOnly: p.ExternalOnly, Notify: p.Notify, Enabled: p.Enabled, CreatedAt: p.CreatedAt}
}

// ListDLPPolicies returns a tenant's data loss prevention policies.
func (s *Admin) ListDLPPolicies(ctx context.Context, in domain.ListDLPPolicies) (domain.DLPPolicies, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.DLPPolicies{}, err
	}
	ps, err := s.Store.DLPPolicies(ctx, tid, false)
	if err != nil {
		return domain.DLPPolicies{}, storeErr(err)
	}
	out := domain.DLPPolicies{Policies: make([]domain.DLPPolicy, len(ps))}
	for i, p := range ps {
		out.Policies[i] = dlpOf(p)
	}
	for _, d := range dlp.Detectors {
		out.Detectors = append(out.Detectors, domain.DLPDetector{Kind: d.Kind, Label: d.Label})
	}
	return out, nil
}

// SaveDLPPolicy creates or replaces a policy.
func (s *Admin) SaveDLPPolicy(ctx context.Context, in domain.SaveDLPPolicy) (domain.DLPPolicySaved, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.DLPPolicySaved{}, err
	}
	p := dlp.Policy{Name: strings.TrimSpace(in.Name), Detector: in.Detector, Pattern: in.Pattern, MinCount: max(in.MinCount, 1),
		Action: string(in.Action), ExternalOnly: in.ExternalOnly, Notify: strings.ToLower(strings.TrimSpace(in.Notify))}
	if err := p.Validate(); err != nil {
		field, msg, _ := strings.Cut(err.Error(), ": ")
		return domain.DLPPolicySaved{}, kakarot.Invalid(msg, map[string]string{field: msg})
	}
	if p.Notify != "" {
		if u, err := s.Store.ResolveRecipient(ctx, p.Notify); err != nil || u.TenantID != tid {
			return domain.DLPPolicySaved{}, kakarot.Invalid("not an address in this tenant", map[string]string{"notify": "use an address in this tenant, or leave it empty for the admins"})
		}
	}
	saved, err := s.Store.SaveDLPPolicy(ctx, store.DLPPolicy{ID: in.ID, TenantID: tid, Name: p.Name, Detector: p.Detector, Pattern: p.Pattern,
		MinCount: p.MinCount, Action: p.Action, ExternalOnly: p.ExternalOnly, Notify: p.Notify, Enabled: in.Enabled})
	if err != nil {
		return domain.DLPPolicySaved{}, storeErr(err)
	}
	return domain.DLPPolicySaved{Policy: dlpOf(saved)}, nil
}

// DeleteDLPPolicy removes a policy.
func (s *Admin) DeleteDLPPolicy(ctx context.Context, in domain.DeleteDLPPolicy) (domain.Done, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.DeleteDLPPolicy(ctx, tid, in.ID))
}

// TestDLP runs the tenant's policies over sample text.
func (s *Admin) TestDLP(ctx context.Context, in domain.TestDLP) (domain.DLPTestResult, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.DLPTestResult{}, err
	}
	ps, err := s.Store.DLPPolicies(ctx, tid, false)
	if err != nil {
		return domain.DLPTestResult{}, storeErr(err)
	}
	var pols []dlp.Policy
	for _, p := range ps {
		pols = append(pols, dlp.Policy{ID: p.ID, Name: p.Name, Detector: p.Detector, Pattern: p.Pattern, MinCount: p.MinCount, Action: p.Action})
	}
	if len(in.Text) > 1<<20 {
		in.Text = in.Text[:1<<20]
	}
	out := domain.DLPTestResult{Matches: []domain.DLPMatch{}}
	for _, m := range dlp.Evaluate(in.Text, pols) {
		out.Matches = append(out.Matches, domain.DLPMatch{PolicyID: m.Policy.ID, Name: m.Policy.Name, Action: domain.DLPAction(m.Policy.Action),
			Count: m.Count, Samples: m.Samples})
	}
	return out, nil
}
