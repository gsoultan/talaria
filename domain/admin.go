// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

import "strings"

// Tenant is an organization with its own domains, users and limits. Limits
// of 0 mean unlimited.
type Tenant struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	SeatLimit      int64  `json:"seatLimit"`
	QuotaBytes     int64  `json:"quotaBytes"`
	DailySendLimit int64  `json:"dailySendLimit"`
	Suspended      bool   `json:"suspended"`
	CreatedAt      int64  `json:"createdAt"`
	Domains        int64  `json:"domains"`
	Users          int64  `json:"users"`
	UsedBytes      int64  `json:"usedBytes"`
}

// Domain is a mail domain of a tenant.
type Domain struct {
	ID        int64  `json:"id"`
	TenantID  int64  `json:"tenantId"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
}

// Alias forwards an address to a user.
type Alias struct {
	ID       int64  `json:"id"`
	TenantID int64  `json:"tenantId"`
	Address  string `json:"address"`
	UserID   int64  `json:"userId"`
}

// TenantScope picks the tenant an admin acts on: 0 is the admin's own.
// Only platform admins may name another tenant.
type TenantScope struct {
	TenantID int64 `json:"-" query:"tenantId"`
}

// ListTenants asks for the tenants the caller may see.
type ListTenants struct{}

// Tenants is a list of tenants.
type Tenants struct {
	Tenants []Tenant `json:"tenants"`
}

// CreateTenant adds a tenant (platform admins only).
type CreateTenant struct {
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	SeatLimit      int64  `json:"seatLimit,omitzero"`
	QuotaBytes     int64  `json:"quotaBytes,omitzero"`
	DailySendLimit int64  `json:"dailySendLimit,omitzero"`
}

// Validate checks the short name.
func (c CreateTenant) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return invalid("name", "enter a short name")
	}
	return nil
}

// TenantCreated is the new tenant.
type TenantCreated struct {
	Tenant Tenant `json:"tenant"`
}

// UpdateTenant changes a tenant's name, limits and suspension.
type UpdateTenant struct {
	ID             int64  `json:"-" path:"id"`
	DisplayName    string `json:"displayName"`
	SeatLimit      int64  `json:"seatLimit"`
	QuotaBytes     int64  `json:"quotaBytes"`
	DailySendLimit int64  `json:"dailySendLimit"`
	Suspended      bool   `json:"suspended"`
}

// DeleteTenant removes a tenant with all its mail.
type DeleteTenant struct {
	ID int64 `json:"-" path:"id"`
}

// ListDomains asks for a tenant's domains.
type ListDomains struct{ TenantScope }

// Domains is a list of domains.
type Domains struct {
	Domains []Domain `json:"domains"`
}

// CreateDomain adds a domain to a tenant.
type CreateDomain struct {
	TenantID int64  `json:"tenantId,omitzero"`
	Name     string `json:"name"`
}

// Validate checks the name.
func (c CreateDomain) Validate() error {
	if !strings.Contains(c.Name, ".") {
		return invalid("name", "enter a domain such as example.com")
	}
	return nil
}

// DomainCreated is the new domain.
type DomainCreated struct {
	Domain Domain `json:"domain"`
}

// DeleteDomain removes a domain, its users and its aliases.
type DeleteDomain struct {
	TenantScope
	ID int64 `json:"-" path:"id"`
}

// DNSRecord is a record the domain needs, and what DNS has now when checked.
type DNSRecord struct {
	Type    string `json:"type"` // MX, TXT, SRV
	Name    string `json:"name"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	OK      bool   `json:"ok"`
	Found   string `json:"found"`
}

// GetDomainSetup lists the DNS records for a domain; Check looks them up.
type GetDomainSetup struct {
	TenantScope
	DomainID int64 `json:"-" path:"domainId"`
	Check    bool  `json:"-" query:"check"`
}

// DomainSetup is the list of records.
type DomainSetup struct {
	Records []DNSRecord `json:"records"`
}

// RotateDKIM makes a new DKIM key for a domain.
type RotateDKIM struct {
	TenantID int64 `json:"tenantId,omitzero"`
	DomainID int64 `json:"-" path:"domainId"`
}

// DKIMRotated is the record to publish for the new key.
type DKIMRotated struct {
	Record DNSRecord `json:"record"`
}

// QueueStatus is where an outgoing message stands.
type QueueStatus string

// Queue states.
const (
	QueueWaiting QueueStatus = "waiting"
	QueueSending QueueStatus = "sending"
	QueueSent    QueueStatus = "sent"
	QueueBounced QueueStatus = "bounced"
)

// QueueItem is one outgoing message to one recipient.
type QueueItem struct {
	ID          int64       `json:"id"`
	From        string      `json:"from"`
	To          string      `json:"to"`
	Status      QueueStatus `json:"status"`
	Attempts    int         `json:"attempts"`
	NextAttempt int64       `json:"nextAttempt"`
	LastError   string      `json:"lastError"`
	Size        int64       `json:"size"`
	CreatedAt   int64       `json:"createdAt"`
	UpdatedAt   int64       `json:"updatedAt"`
}

// ListQueue asks for outgoing mail; an empty Status lists every state.
type ListQueue struct {
	TenantScope
	Status QueueStatus `json:"-" query:"status"`
	Limit  int         `json:"-" query:"limit"`
}

// Queue is outgoing mail with today's counts and where it goes.
type Queue struct {
	Items        []QueueItem `json:"items"`
	Waiting      int64       `json:"waiting"`
	SentToday    int64       `json:"sentToday"`
	BouncedToday int64       `json:"bouncedToday"`
	Route        string      `json:"route"`
}

// RetryQueue tries a waiting message now; ID 0 retries every waiting one.
type RetryQueue struct {
	TenantID int64 `json:"tenantId,omitzero"`
	ID       int64 `json:"id,omitzero"`
}

// CancelQueue stops trying a message and bounces it to the sender.
type CancelQueue struct {
	TenantID int64 `json:"tenantId,omitzero"`
	ID       int64 `json:"id"`
}

// GetStats asks for a tenant's numbers, or with Server the whole server's
// (platform admins only).
type GetStats struct {
	TenantScope
	Server bool `json:"-" query:"server"`
}

// Stats are the dashboard numbers. Seat and quota limits are set for a
// tenant; memory and uptime for the server.
type Stats struct {
	Tenants          int64  `json:"tenants"`
	Domains          int64  `json:"domains"`
	Users            int64  `json:"users"`
	SeatLimit        int64  `json:"seatLimit"`
	QuotaBytes       int64  `json:"quotaBytes"`
	UsedBytes        int64  `json:"usedBytes"`
	StoredBytes      int64  `json:"storedBytes"` // on disk, compressed and deduplicated
	RawBytes         int64  `json:"rawBytes"`    // before compression
	ReceivedToday    int64  `json:"receivedToday"`
	JunkToday        int64  `json:"junkToday"`
	QueueWaiting     int64  `json:"queueWaiting"`
	SentToday        int64  `json:"sentToday"`
	BouncedToday     int64  `json:"bouncedToday"`
	HeapBytes        int64  `json:"heapBytes"`
	MemoryLimitBytes int64  `json:"memoryLimitBytes"`
	UptimeSeconds    int64  `json:"uptimeSeconds"`
	Route            string `json:"route"`
}

// ListUsers asks for a tenant's users.
type ListUsers struct{ TenantScope }

// Users is a list of users.
type Users struct {
	Users []User `json:"users"`
}

// CreateUser adds a user to a tenant.
type CreateUser struct {
	TenantID    int64  `json:"tenantId,omitzero"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName,omitzero"`
	Password    string `json:"password"`
	Role        Role   `json:"role,omitzero"` // default user
	QuotaBytes  int64  `json:"quotaBytes,omitzero"`
}

// Validate checks the address, password and role.
func (c CreateUser) Validate() error {
	if !strings.Contains(c.Email, "@") {
		return invalid("email", "enter an email address")
	}
	if len(c.Password) < 8 {
		return invalid("password", "use at least 8 characters")
	}
	if c.Role != "" && !c.Role.Valid() {
		return invalid("role", "unknown role")
	}
	return nil
}

// UserCreated is the new user.
type UserCreated struct {
	User User `json:"user"`
}

// UpdateUser changes a user's name, role, quota and suspension.
type UpdateUser struct {
	ID          int64  `json:"-" path:"id"`
	DisplayName string `json:"displayName"`
	Role        Role   `json:"role"`
	QuotaBytes  int64  `json:"quotaBytes"`
	Suspended   bool   `json:"suspended"`
}

// Validate checks the role.
func (u UpdateUser) Validate() error {
	if !u.Role.Valid() {
		return invalid("role", "unknown role")
	}
	return nil
}

// SetUserPassword sets a new password for a user and signs them out.
type SetUserPassword struct {
	ID       int64  `json:"-" path:"id"`
	Password string `json:"password"`
}

// Validate checks the length.
func (s SetUserPassword) Validate() error {
	if len(s.Password) < 8 {
		return invalid("password", "use at least 8 characters")
	}
	return nil
}

// DeleteUser removes a user and their mail.
type DeleteUser struct {
	ID int64 `json:"-" path:"id"`
}

// ListAliases asks for a tenant's aliases, or one user's when UserID is set.
type ListAliases struct {
	TenantScope
	UserID int64 `json:"-" query:"userId"`
}

// Aliases is a list of aliases.
type Aliases struct {
	Aliases []Alias `json:"aliases"`
}

// CreateAlias forwards an address to a user.
type CreateAlias struct {
	TenantID int64  `json:"tenantId,omitzero"`
	Address  string `json:"address"`
	UserID   int64  `json:"userId"`
}

// AliasCreated is the new alias.
type AliasCreated struct {
	Alias Alias `json:"alias"`
}

// DeleteAlias removes an alias.
type DeleteAlias struct {
	TenantScope
	ID int64 `json:"-" path:"id"`
}
