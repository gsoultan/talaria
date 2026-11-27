// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Badge, Button, FileButton, Group, Modal, PasswordInput, Stack, Table, Text, Textarea, Title } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { ConfirmButton } from '../admin/confirm'
import { ofOps, useApiMutation, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { importIdentity, removeIdentity, useIdentities, useRefreshIdentities } from '../../lib/smime'

const day = (ms: number) => new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

function ImportIdentity({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const refresh = useRefreshIdentities()
  const qc = useQueryClient()
  const publish = useApiMutation('mail.ImportCertificate')
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        if (!file) return
        setBusy(true)
        setError('')
        try {
          const id = await importIdentity(file, password)
          await refresh()
          // Publish the certificate (public), so colleagues can encrypt to you.
          await publish.mutateAsync({ data: id.chain.join('\n'), own: true }).catch(() => undefined)
          void qc.invalidateQueries({ predicate: ofOps('mail.ListCertificates') })
          notifications.show({ color: 'green', message: `You can now sign and decrypt as ${id.emails.join(', ')} in this browser.` })
          onClose()
        } catch (err) {
          setError(errorText(err))
        } finally {
          setBusy(false)
        }
      }}
    >
      <Stack>
        <Text size="sm">
          Choose your certificate file (.p12 or .pfx) and enter its password. Your private key is kept only in this browser, encrypted, and never sent to the server. Import it again on each browser
          you use.
        </Text>
        <Group>
          <FileButton onChange={setFile} accept=".p12,.pfx,application/x-pkcs12">
            {(props) => (
              <Button variant="default" {...props}>
                Choose file
              </Button>
            )}
          </FileButton>
          <Text size="sm" c={file ? undefined : 'dimmed'}>
            {file?.name ?? 'No file chosen'}
          </Text>
        </Group>
        <PasswordInput label="File password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="off" />
        {error && (
          <Alert color="red" variant="light">
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={busy} disabled={!file}>
            Import
          </Button>
        </Group>
      </Stack>
    </form>
  )
}

function AddContactCert({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [data, setData] = useState('')
  const add = useApiMutation('mail.ImportCertificate', {
    onSuccess: () => {
      void qc.invalidateQueries({ predicate: ofOps('mail.ListCertificates') })
      onClose()
    },
  })
  return (
    <Stack>
      <Text size="sm">Paste a certificate (PEM, starting with -----BEGIN CERTIFICATE-----) or choose a .cer, .crt or .pem file. Certificates also arrive by themselves when someone sends you signed mail.</Text>
      <FileButton
        onChange={async (f) => {
          if (!f) return
          const buf = new Uint8Array(await f.arrayBuffer())
          const txt = new TextDecoder().decode(buf)
          setData(txt.includes('-----BEGIN') ? txt : btoa(String.fromCharCode(...buf)))
        }}
        accept=".cer,.crt,.pem,.der"
      >
        {(props) => (
          <Button variant="default" w="fit-content" {...props}>
            Choose file
          </Button>
        )}
      </FileButton>
      <Textarea aria-label="Certificate" autosize minRows={4} maxRows={10} value={data} onChange={(e) => setData(e.currentTarget.value)} styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } }} />
      {add.error && (
        <Alert color="red" variant="light">
          {errorText(add.error)}
        </Alert>
      )}
      <Group justify="flex-end">
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button loading={add.isPending} disabled={!data.trim()} onClick={() => add.mutate({ data })}>
          Add
        </Button>
      </Group>
    </Stack>
  )
}

const sourceLabel: Record<string, string> = { own: 'Yours', imported: 'Added', harvested: 'From signed mail' }

export function SmimeSettings() {
  const ids = useIdentities()
  const refresh = useRefreshIdentities()
  const qc = useQueryClient()
  const certs = useApiQuery('mail.ListCertificates', {})
  const del = useApiMutation('mail.DeleteCertificate', { onSuccess: () => void qc.invalidateQueries({ predicate: ofOps('mail.ListCertificates') }) })
  const [dialog, setDialog] = useState<'identity' | 'contact' | null>(null)
  return (
    <Stack gap="lg">
      <div>
        <Group justify="space-between" mb="xs">
          <Title order={4}>Your certificate in this browser</Title>
          <Button size="xs" variant="default" onClick={() => setDialog('identity')}>
            Import .p12
          </Button>
        </Group>
        {ids.data?.length === 0 && (
          <Text size="sm" c="dimmed">
            None yet. With your own S/MIME certificate you can sign mail, and read mail encrypted to you. Get one from your organisation or a certificate authority.
          </Text>
        )}
        {ids.error && (
          <Alert color="red" variant="light">
            This browser cannot keep keys: {errorText(ids.error)}
          </Alert>
        )}
        {ids.data?.map((i) => (
          <Group key={i.id} justify="space-between" py={6} wrap="nowrap">
            <div>
              <Text size="sm" fw={500}>
                {i.emails.join(', ')}
              </Text>
              <Text size="xs" c="dimmed">
                Issued by {i.issuer} · {i.notAfter < Date.now() ? 'expired' : 'valid until'} {day(i.notAfter)}
              </Text>
            </div>
            <ConfirmButton
              size="compact-xs"
              variant="subtle"
              color="red"
              label="Remove"
              title="Remove your key from this browser?"
              body="You will no longer be able to sign here, or read mail encrypted to this certificate, until you import the .p12 file again."
              confirm="Remove"
              onConfirm={async () => {
                await removeIdentity(i.id)
                await refresh()
              }}
            />
          </Group>
        ))}
      </div>
      <div>
        <Group justify="space-between" mb="xs">
          <Title order={4}>Certificates</Title>
          <Button size="xs" variant="default" onClick={() => setDialog('contact')}>
            Add certificate
          </Button>
        </Group>
        <Text size="sm" c="dimmed" mb="xs">
          To encrypt to someone, you need their certificate. Talaria keeps the ones from signed mail you receive, and finds those your colleagues published.
        </Text>
        <Table.ScrollContainer minWidth={560}>
          <Table verticalSpacing={6}>
            <Table.Tbody>
              {certs.data?.certificates.map((c) => (
                <Table.Tr key={c.id}>
                  <Table.Td>
                    <Text size="sm">{c.email}</Text>
                    <Text size="xs" c="dimmed">
                      {c.issuer} · until {day(Number(c.notAfter) * 1000)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      <Badge variant="light" color="gray" tt="none" size="sm">
                        {sourceLabel[c.source] ?? c.source}
                      </Badge>
                      {c.problem && (
                        <Badge variant="light" color="orange" tt="none" size="sm" title={c.problem}>
                          Not trusted
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Button size="compact-xs" variant="subtle" color="red" onClick={() => del.mutate({ id: c.id })}>
                      Delete
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
              {certs.data?.certificates.length === 0 && (
                <Table.Tr>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      No certificates yet.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </div>
      <Modal opened={dialog !== null} onClose={() => setDialog(null)} title={dialog === 'identity' ? 'Import your certificate' : 'Add a certificate'} centered>
        {dialog === 'identity' ? <ImportIdentity onClose={() => setDialog(null)} /> : <AddContactCert onClose={() => setDialog(null)} />}
      </Modal>
    </Stack>
  )
}
