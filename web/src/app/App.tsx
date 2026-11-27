// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Center, Loader, Notification, Stack, Text } from '@mantine/core'
import { Notifications } from '@mantine/notifications'
import { Suspense, lazy, useEffect, useState, type ReactNode } from 'react'
import { LoginPage } from '../features/auth/LoginPage'
import { isAdmin, isPlatformAdmin, useMe } from '../features/auth/useMe'
import { ComposeWindow } from '../features/mail/ComposeWindow'
import { MailboxPage, StarredPage } from '../features/mail/MailPage'
import { SearchPage } from '../features/mail/SearchPage'
import { Shell } from '../features/mail/Shell'
import { ThreadPage } from '../features/mail/ThreadPage'
import { errorText, isUnauthenticated } from '../lib/errors'
import { useLive } from '../lib/live'
import { registerServiceWorker } from '../lib/registerSW'
import { match, navigate, useLocation } from '../lib/router'

// Admin and settings load on first use, so the inbox ships less code.
const AdminShell = lazy(() => import('../features/admin/AdminShell').then((m) => ({ default: m.AdminShell })))
const DomainsPage = lazy(() => import('../features/admin/DomainsPage').then((m) => ({ default: m.DomainsPage })))
const UsersPage = lazy(() => import('../features/admin/UsersPage').then((m) => ({ default: m.UsersPage })))
const QueuePage = lazy(() => import('../features/admin/QueuePage').then((m) => ({ default: m.QueuePage })))
const FilteringPage = lazy(() => import('../features/admin/FilteringPage').then((m) => ({ default: m.FilteringPage })))
const QuarantineAdminPage = lazy(() => import('../features/admin/QuarantineAdminPage').then((m) => ({ default: m.QuarantineAdminPage })))
const QuarantinePage = lazy(() => import('../features/quarantine/QuarantinePage').then((m) => ({ default: m.QuarantinePage })))
const TenantsPage = lazy(() => import('../features/admin/TenantsPage').then((m) => ({ default: m.TenantsPage })))
const SettingsPage = lazy(() => import('../features/settings/SettingsPage').then((m) => ({ default: m.SettingsPage })))

const spinner = (
  <Center style={{ flex: 1 }} h="100%">
    <Loader size="sm" />
  </Center>
)

function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, { replace: true }), [to])
  return null
}

function UpdateToast() {
  const [update, setUpdate] = useState<(() => void) | null>(null)
  useEffect(() => registerServiceWorker((fn) => setUpdate(() => fn)), [])
  if (!update) return null
  return (
    <Notification title="A new version is ready" onClose={() => setUpdate(null)} style={{ position: 'fixed', left: 16, bottom: 16, zIndex: 400, maxWidth: 340 }}>
      <Button size="xs" mt="xs" onClick={update}>
        Reload
      </Button>
    </Notification>
  )
}

function Routes() {
  const { path, query } = useLocation()
  const me = useMe().data?.user
  let p: Record<string, string> | null

  if (path === '/' || path === '/mail' || path === '/login') return <Redirect to="/mail/inbox" />

  if (path.startsWith('/admin')) {
    if (!isAdmin(me)) return <Redirect to="/mail/inbox" />
    let page: ReactNode
    if (path === '/admin' || path === '/admin/') page = <Redirect to="/admin/domains" />
    else if (path === '/admin/domains') page = <DomainsPage />
    else if (path === '/admin/users') page = <UsersPage />
    else if (path === '/admin/queue') page = <QueuePage />
    else if (path === '/admin/filtering') page = <FilteringPage />
    else if (path === '/admin/quarantine') page = <QuarantineAdminPage />
    else if (path === '/admin/tenants' && isPlatformAdmin(me)) page = <TenantsPage />
    else page = <Redirect to="/admin/domains" />
    return (
      <Suspense fallback={spinner}>
        <AdminShell>
          <Suspense fallback={spinner}>{page}</Suspense>
        </AdminShell>
      </Suspense>
    )
  }

  let page: ReactNode
  if ((p = match('/mail/:box/:msg?', path))) page = <MailboxPage key={p.box} slug={p.box!} messageId={p.msg} />
  else if ((p = match('/starred/:msg?', path))) page = <StarredPage messageId={p.msg} />
  else if (path === '/search') page = <SearchPage q={query.get('q') ?? ''} messageId={query.get('m') ?? undefined} />
  else if ((p = match('/thread/:id', path)) && /^\d+$/.test(p.id!)) page = <ThreadPage id={p.id!} />
  else if (path === '/quarantine')
    page = (
      <Suspense fallback={spinner}>
        <QuarantinePage />
      </Suspense>
    )
  else if ((p = match('/settings/:section?', path)))
    page = (
      <Suspense fallback={spinner}>
        <SettingsPage section={p.section} />
      </Suspense>
    )
  else page = <Redirect to="/mail/inbox" />
  return <SignedIn>{page}</SignedIn>
}

function SignedIn({ children }: { children: ReactNode }) {
  const live = useLive(true)
  return (
    <>
      <Shell live={live}>{children}</Shell>
      <ComposeWindow />
    </>
  )
}

export function App() {
  const me = useMe()
  let body: ReactNode
  // A refetch after an error resets the query to pending; keep showing the
  // sign-in form then, or it would lose what was typed.
  const signedOut = (me.error && isUnauthenticated(me.error)) || (me.isPending && me.errorUpdateCount > 0 && !me.data)
  if (signedOut) body = <LoginPage />
  else if (me.data?.user) body = <Routes />
  else if (me.isPending) {
    body = (
      <Center h="100%">
        <Loader />
      </Center>
    )
  } else if (me.error && !isUnauthenticated(me.error)) {
    body = (
      <Center h="100%" p="xl">
        <Stack align="center">
          <Text>{errorText(me.error)}</Text>
          <Button variant="default" onClick={() => void me.refetch()}>
            Try again
          </Button>
        </Stack>
      </Center>
    )
  } else body = <LoginPage />
  return (
    <>
      <Notifications position="bottom-center" limit={3} />
      {body}
      <UpdateToast />
    </>
  )
}
