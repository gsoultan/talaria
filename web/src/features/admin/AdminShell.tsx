// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Anchor, Badge, Box, Group, NavLink, Paper, ScrollArea, Select, SimpleGrid, Stack, Text, Title } from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import type { ReactNode } from 'react'
import { LogoMark } from '../../components/Logo'
import { bytes } from '../../lib/format'
import { Link, navigate, useLocation } from '../../lib/router'
import { isPlatformAdmin, useMe } from '../auth/useMe'
import { useApiQuery } from '../../lib/api'

/** The tenant being administered: ?tenant= for platform admins, else their own. */
export function useTenant(): number {
  const { query } = useLocation()
  const me = useMe().data?.user
  const t = query.get('tenant')
  if (t && isPlatformAdmin(me)) return Number(t)
  return me?.tenantId ?? 0
}

export function withTenant(path: string, tenant: number, own: number): string {
  return tenant === own ? path : `${path}?tenant=${tenant}`
}

function TenantPicker() {
  const me = useMe().data?.user
  const { path } = useLocation()
  const tenant = useTenant()
  const list = useApiQuery('admin.ListTenants', {}, { enabled: isPlatformAdmin(me) }).data?.tenants ?? []
  if (!isPlatformAdmin(me) || list.length < 2) return null
  return (
    <Select
      aria-label="Tenant"
      size="xs"
      w={200}
      value={tenant.toString()}
      allowDeselect={false}
      data={list.map((t) => ({ value: t.id.toString(), label: t.displayName }))}
      onChange={(v) => v && navigate(withTenant(path, Number(v), me!.tenantId))}
    />
  )
}

export function StatCard({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <Paper className="t-pane" p="md" radius="lg">
      <Text size="xs" c="dimmed" fw={600} tt="uppercase">
        {label}
      </Text>
      <Text fw={700} size="xl" mt={4}>
        {value}
      </Text>
      {sub && (
        <Text size="xs" c="dimmed">
          {sub}
        </Text>
      )}
    </Paper>
  )
}

export function Health() {
  const me = useMe().data?.user
  const tenant = useTenant()
  const server = isPlatformAdmin(me) && tenant === me?.tenantId
  const s = useApiQuery('admin.GetStats', { tenantId: tenant, server }, { refetchInterval: 30_000 }).data
  if (!s) return <SimpleGrid cols={{ base: 2, md: 4 }} h={92} />
  const saved = s.rawBytes > 0 ? Math.round((1 - Number(s.storedBytes) / Number(s.rawBytes)) * 100) : 0
  return (
    <SimpleGrid cols={{ base: 2, md: 4 }}>
      {server ? (
        <StatCard label="Memory" value={bytes(s.heapBytes)} sub={s.memoryLimitBytes > 0 && s.memoryLimitBytes < 1 << 60 ? `of ${bytes(s.memoryLimitBytes)} limit` : 'no limit set'} />
      ) : (
        <StatCard label="Seats" value={`${s.users}${s.seatLimit > 0 ? ` of ${s.seatLimit}` : ''}`} sub={`${s.domains} domains`} />
      )}
      <StatCard label="Disk" value={bytes(s.storedBytes)} sub={s.rawBytes > 0 ? `from ${bytes(s.rawBytes)} raw mail, ${saved}% saved` : 'no mail yet'} />
      <StatCard label="Queue" value={s.queueWaiting.toString()} sub={`${s.sentToday.toLocaleString()} sent today, ${s.bouncedToday} bounced`} />
      <StatCard label="Today" value={s.receivedToday.toLocaleString()} sub={`received, ${s.junkToday.toLocaleString()} spam`} />
    </SimpleGrid>
  )
}

export function AdminShell({ children }: { children: ReactNode }) {
  const me = useMe().data?.user
  const { path } = useLocation()
  const tenant = useTenant()
  const narrow = useMediaQuery('(max-width: 62em)', false)
  const own = me?.tenantId ?? 0
  const items = [
    { to: '/admin/domains', label: 'Domains' },
    { to: '/admin/users', label: 'Users' },
    { to: '/admin/queue', label: 'Outbound queue' },
    { to: '/admin/filtering', label: 'Sender filtering' },
    ...(isPlatformAdmin(me) ? [{ to: '/admin/tenants', label: 'Tenants' }] : []),
  ]
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <header style={{ height: 56, flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 12, padding: '0 16px', background: 'var(--t-surface)', borderBottom: '1px solid var(--t-border)' }}>
        <LogoMark />
        <Text fw={700} size="lg">
          Talaria
        </Text>
        <Badge variant="light" radius="sm" tt="none">
          {isPlatformAdmin(me) ? 'Platform admin' : 'Tenant admin'}
        </Badge>
        <Group ml="auto" gap="md">
          <TenantPicker />
          <Anchor component={Link} to="/mail/inbox" size="sm">
            Back to mail
          </Anchor>
        </Group>
      </header>
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: narrow ? 'column' : 'row' }}>
        <nav aria-label="Admin" style={{ width: narrow ? 'auto' : 220, padding: narrow ? '8px 8px 0' : 16, display: 'flex', flexDirection: narrow ? 'row' : 'column', gap: 2, overflowX: 'auto' }}>
          {items.map((i) => (
            <NavLink key={i.to} component={Link} to={withTenant(i.to, tenant, own)} label={i.label} active={path.startsWith(i.to)} style={{ borderRadius: 8, whiteSpace: 'nowrap' }} w={narrow ? 'auto' : undefined} />
          ))}
        </nav>
        <ScrollArea style={{ flex: 1 }}>
          <Box p={narrow ? 'sm' : 'lg'} maw={1200}>
            {children}
          </Box>
        </ScrollArea>
      </div>
    </div>
  )
}

export function PageTitle({ title, sub, right }: { title: string; sub?: ReactNode; right?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-end" mb="md" mt="lg">
      <Stack gap={2}>
        <Title order={2}>{title}</Title>
        {sub && (
          <Text size="sm" c="dimmed">
            {sub}
          </Text>
        )}
      </Stack>
      {right}
    </Group>
  )
}
