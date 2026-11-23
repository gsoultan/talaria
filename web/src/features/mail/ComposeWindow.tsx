// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { MessageInitShape } from '@bufbuild/protobuf'
import { useMutation, useQuery } from '@connectrpc/connect-query'
import { ActionIcon, Alert, Anchor, Box, Button, CloseButton, Group, Paper, Portal, Select, Stack, TagsInput, Text, TextInput, Textarea, Tooltip } from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import { useForm, useStore } from '@tanstack/react-form'
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { MailService, type ComposeSchema } from '../../gen/talaria/v1/mail_pb'
import { errorText, isNetworkError } from '../../lib/errors'
import { bytes } from '../../lib/format'
import { queueOffline } from '../../lib/outbox'
import { useMe } from '../auth/useMe'
import { closeCompose, useCompose, type Draft } from './composeStore'
import { Icon, icons } from './Shell'

type File_ = { name: string; type: string; size: number; data: Uint8Array }

const MAX_TOTAL = 25 * 1024 * 1024
const emailish = /^(?:[^<>@]*<)?[^<>@\s]+@[^<>@\s]+\.[^<>@\s]+>?$/

function invalid(list: string[]): string | undefined {
  const bad = list.find((a) => !emailish.test(a.trim()))
  return bad ? `“${bad}” is not an email address` : undefined
}

function Composer({ draft }: { draft: Draft }) {
  const qc = useQueryClient()
  const me = useMe().data?.user
  const identities = useQuery(MailService.method.listIdentities, {}, { staleTime: 10 * 60_000 }).data?.identities ?? []
  const send = useMutation(MailService.method.sendMessage)
  const save = useMutation(MailService.method.saveDraft)
  const [files, setFiles] = useState<File_[]>([])
  const [showCc, setShowCc] = useState(draft.cc.length > 0 || draft.bcc.length > 0)
  const [draftId, setDraftId] = useState(draft.draftId ?? 0n)
  const [savedAt, setSavedAt] = useState<Date | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const phone = useMediaQuery('(max-width: 48em)', false)

  const fromOptions = identities.map((i) => ({ value: i.address, label: i.displayName ? `${i.displayName} <${i.address}>` : i.address }))
  const form = useForm({
    defaultValues: {
      from: draft.from ?? me?.email ?? '',
      to: draft.to,
      cc: draft.cc,
      bcc: draft.bcc,
      subject: draft.subject,
      body: draft.body,
    },
    onSubmit: async ({ value }) => {
      setError(null)
      const msg = build(value)
      try {
        const res = await send.mutateAsync({ message: msg })
        notifications.show({
          color: 'green',
          message: res.queued > 0 ? 'Sent. Outside recipients get it in a moment.' : 'Sent',
          autoClose: 3000,
        })
        void qc.invalidateQueries({ predicate: (q) => ['ListMailboxes', 'ListMessages'].includes((q.queryKey[1] as { methodName?: string })?.methodName ?? '') })
        closeCompose()
      } catch (err) {
        if (isNetworkError(err)) {
          await queueOffline(msg)
          notifications.show({ color: 'orange', message: 'You’re offline. It’s in the outbox and sends when you reconnect.' })
          closeCompose()
          return
        }
        setError(errorText(err))
      }
    },
  })

  const build = (v: typeof form.state.values, id = draftId): MessageInitShape<typeof ComposeSchema> => ({
    from: v.from,
    to: v.to,
    cc: v.cc,
    bcc: v.bcc,
    subject: v.subject,
    textBody: v.body,
    inReplyTo: draft.inReplyTo ?? '',
    references: draft.references ?? [],
    attachments: files.map((f) => ({ filename: f.name, contentType: f.type || 'application/octet-stream', data: f.data })),
    draftId: id,
  })

  // Saves a draft a few seconds after typing stops.
  const values = useStore(form.store, (s) => s.values)
  const dirty = useStore(form.store, (s) => s.isDirty)
  useEffect(() => {
    if (!dirty || !navigator.onLine) return
    const t = setTimeout(() => {
      if (form.state.isSubmitting) return
      save.mutate(
        { message: build(values) },
        {
          onSuccess: (r) => {
            setDraftId(r.draftId)
            setSavedAt(new Date())
          },
        },
      )
    }, 4000)
    return () => clearTimeout(t)
  }, [values, dirty, files])

  const total = files.reduce((n, f) => n + f.size, 0)
  const addFiles = async (list: FileList | null) => {
    if (!list) return
    const add: File_[] = []
    for (const f of Array.from(list)) add.push({ name: f.name, type: f.type, size: f.size, data: new Uint8Array(await f.arrayBuffer()) })
    setFiles((cur) => [...cur, ...add])
  }

  return (
    <form
      style={{ display: 'flex', flexDirection: 'column', height: '100%' }}
      onSubmit={(e) => {
        e.preventDefault()
        void form.handleSubmit()
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
          e.preventDefault()
          void form.handleSubmit()
        }
        if (e.key === 'Escape') closeCompose()
      }}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault()
        void addFiles(e.dataTransfer.files)
      }}
    >
      <Group justify="space-between" px="md" py="xs" style={{ borderBottom: '1px solid var(--t-border)' }}>
        <Text fw={600}>{draft.subject ? draft.subject : 'New message'}</Text>
        <Group gap="xs">
          {savedAt && (
            <Text size="xs" c="dimmed">
              Draft saved {savedAt.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}
            </Text>
          )}
          <CloseButton aria-label="Close" onClick={closeCompose} />
        </Group>
      </Group>
      <Stack gap={6} px="md" py="sm" style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
        {fromOptions.length > 1 && (
          <form.Field name="from">
            {(f) => <Select label="From" data={fromOptions} value={f.state.value} onChange={(v) => v && f.handleChange(v)} allowDeselect={false} size="sm" />}
          </form.Field>
        )}
        <form.Field name="to" validators={{ onSubmit: ({ value, fieldApi }) => (value.length + fieldApi.form.getFieldValue('cc').length + fieldApi.form.getFieldValue('bcc').length === 0 ? 'Add at least one recipient' : invalid(value)) }}>
          {(f) => (
            <TagsInput
              label="To"
              value={f.state.value}
              onChange={f.handleChange}
              splitChars={[',', ';', ' ']}
              acceptValueOnBlur
              autoFocus={draft.to.length === 0}
              error={f.state.meta.errors[0]}
              size="sm"
              rightSectionWidth={showCc ? undefined : 64}
              rightSection={
                !showCc && (
                  <Anchor size="xs" onClick={() => setShowCc(true)} style={{ whiteSpace: 'nowrap' }}>
                    Cc Bcc
                  </Anchor>
                )
              }
            />
          )}
        </form.Field>
        {showCc && (
          <Group grow align="flex-start">
            <form.Field name="cc" validators={{ onSubmit: ({ value }) => invalid(value) }}>
              {(f) => <TagsInput label="Cc" value={f.state.value} onChange={f.handleChange} splitChars={[',', ';', ' ']} acceptValueOnBlur error={f.state.meta.errors[0]} size="sm" />}
            </form.Field>
            <form.Field name="bcc" validators={{ onSubmit: ({ value }) => invalid(value) }}>
              {(f) => <TagsInput label="Bcc" value={f.state.value} onChange={f.handleChange} splitChars={[',', ';', ' ']} acceptValueOnBlur error={f.state.meta.errors[0]} size="sm" />}
            </form.Field>
          </Group>
        )}
        <form.Field name="subject">
          {(f) => <TextInput label="Subject" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} size="sm" />}
        </form.Field>
        <form.Field name="body">
          {(f) => (
            <Textarea
              aria-label="Message"
              value={f.state.value}
              onChange={(e) => f.handleChange(e.currentTarget.value)}
              autoFocus={draft.to.length > 0}
              onFocus={(e) => draft.body.startsWith('\n') && e.currentTarget.setSelectionRange(0, 0)}
              styles={{ input: { minHeight: 220, lineHeight: 1.55 } }}
              autosize
              minRows={9}
              mt={6}
            />
          )}
        </form.Field>
        {files.length > 0 && (
          <Group gap="xs">
            {files.map((f, i) => (
              <Paper key={i} withBorder px="xs" py={4} radius="md" style={{ display: 'flex', alignItems: 'center', gap: 6, maxWidth: 260 }}>
                <Icon d={icons.paperclip} size={14} />
                <Text size="xs" truncate>
                  {f.name}
                </Text>
                <Text size="xs" c="dimmed">
                  {bytes(f.size)}
                </Text>
                <CloseButton size="xs" aria-label={`Remove ${f.name}`} onClick={() => setFiles((cur) => cur.filter((_, j) => j !== i))} />
              </Paper>
            ))}
          </Group>
        )}
        {total > MAX_TOTAL && (
          <Alert color="orange" variant="light" p="xs">
            Attachments add up to {bytes(total)}. Many mail servers refuse messages over 25 MB.
          </Alert>
        )}
        {error && (
          <Alert color="red" variant="light" p="xs" role="alert">
            {error}
          </Alert>
        )}
      </Stack>
      <Group px="md" py="sm" gap="xs" style={{ borderTop: '1px solid var(--t-border)' }}>
        <form.Subscribe selector={(s) => s.isSubmitting}>
          {(busy) => (
            <Button type="submit" loading={busy} leftSection={<Icon d={icons.sent} size={15} />}>
              Send
            </Button>
          )}
        </form.Subscribe>
        <Tooltip label="Attach files">
          <ActionIcon variant="subtle" color="gray" size="lg" onClick={() => fileInput.current?.click()} aria-label="Attach files">
            <Icon d={icons.paperclip} />
          </ActionIcon>
        </Tooltip>
        <input ref={fileInput} type="file" multiple hidden onChange={(e) => void addFiles(e.currentTarget.files).then(() => (e.currentTarget.value = ''))} />
        {!phone && (
          <Text size="xs" c="dimmed" ml="auto">
            Ctrl + Enter sends. Offline? It goes in the outbox and sends when you reconnect.
          </Text>
        )}
      </Group>
    </form>
  )
}

/** A floating compose panel on desktop, full screen on phones. */
export function ComposeWindow() {
  const draft = useCompose()
  const phone = useMediaQuery('(max-width: 48em)', false)
  if (!draft) return null
  return (
    <Portal>
      <Paper
        shadow="xl"
        radius={phone ? 0 : 'lg'}
        withBorder={!phone}
        role="dialog"
        aria-label="Compose message"
        style={{
          position: 'fixed',
          zIndex: 300,
          background: 'var(--t-surface)',
          overflow: 'hidden',
          ...(phone ? { inset: 0 } : { right: 24, bottom: 0, width: 'min(640px, calc(100vw - 48px))', height: 'min(680px, calc(100vh - 80px))', borderBottomLeftRadius: 0, borderBottomRightRadius: 0 }),
        }}
      >
        <Box h="100%">
          <Composer key={draft.key} draft={draft} />
        </Box>
      </Paper>
    </Portal>
  )
}
