// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

// DLPAction is what a data loss prevention policy does with a message
// that matches.
type DLPAction string

// Policy actions.
const (
	// DLPBlock refuses the message.
	DLPBlock DLPAction = "block"
	// DLPWarn asks the sender to confirm in the webmail. Mail apps cannot
	// ask, so their mail is sent.
	DLPWarn DLPAction = "warn"
	// DLPEncrypt sends the message only over a verified encrypted
	// connection.
	DLPEncrypt DLPAction = "encrypt"
	// DLPNotify sends it and tells the policy's contact.
	DLPNotify DLPAction = "notify"
)

// DLPPolicy is a tenant's rule for outgoing mail.
type DLPPolicy struct {
	ID       int64  `json:"id"`
	TenantID int64  `json:"tenantId"`
	Name     string `json:"name"`
	// Detector is credit_card, iban, us_ssn, id_nik, pattern or keywords.
	Detector string `json:"detector"`
	// Pattern is the regular expression, or the keywords one per line.
	Pattern      string    `json:"pattern"`
	MinCount     int       `json:"minCount"`
	Action       DLPAction `json:"action"`
	ExternalOnly bool      `json:"externalOnly"`
	// Notify is a local address for notices; empty means the tenant's admins.
	Notify    string `json:"notify"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"createdAt"`
}

// DLPDetector is a kind of sensitive data the server can find.
type DLPDetector struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// ListDLPPolicies asks for a tenant's policies.
type ListDLPPolicies struct {
	TenantScope
}

// DLPPolicies is a tenant's policies and the detectors to choose from.
type DLPPolicies struct {
	Policies  []DLPPolicy   `json:"policies"`
	Detectors []DLPDetector `json:"detectors"`
}

// SaveDLPPolicy creates a policy, or replaces one when ID is set.
type SaveDLPPolicy struct {
	TenantID     int64     `json:"tenantId,omitzero"`
	ID           int64     `json:"id,omitzero"`
	Name         string    `json:"name"`
	Detector     string    `json:"detector"`
	Pattern      string    `json:"pattern,omitzero"`
	MinCount     int       `json:"minCount,omitzero"`
	Action       DLPAction `json:"action"`
	ExternalOnly bool      `json:"externalOnly"`
	Notify       string    `json:"notify,omitzero"`
	Enabled      bool      `json:"enabled"`
}

// DLPPolicySaved is the saved policy.
type DLPPolicySaved struct {
	Policy DLPPolicy `json:"policy"`
}

// DeleteDLPPolicy removes a policy.
type DeleteDLPPolicy struct {
	TenantScope
	ID int64 `json:"-" path:"id"`
}

// TestDLP runs a tenant's policies, enabled or not, over sample text.
type TestDLP struct {
	TenantID int64  `json:"tenantId,omitzero"`
	Text     string `json:"text"`
}

// DLPMatch is a policy that matched, with masked samples.
type DLPMatch struct {
	PolicyID int64     `json:"policyId"`
	Name     string    `json:"name"`
	Action   DLPAction `json:"action"`
	Count    int       `json:"count"`
	Samples  []string  `json:"samples"`
}

// DLPTestResult lists the policies the text matched, strongest first.
type DLPTestResult struct {
	Matches []DLPMatch `json:"matches"`
}
