// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Anchor, Badge, Button, Center, Group, Loader, Paper, Text, Tooltip } from '@mantine/core'
import PostalMime from 'postal-mime'
import { useEffect, useState } from 'react'
import { type MessageDetail, type SMIMEStatus, useApiMutation } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { bytes } from '../../lib/format'
import { Link } from '../../lib/router'
import { type SignatureInfo, decryptMessage } from '../../lib/smime'
import { MessageBody } from './MessageBody'
import { Attachments } from './Reader'

function SignatureBadge({ s }: { s: { verified: boolean; signer: string; problem: string; encrypted?: boolean } }) {
  return (
    <Group gap={6} mb="sm">
      {s.encrypted && (
        <Badge color="teal" variant="light" tt="none" radius="sm">
          Encrypted
        </Badge>
      )}
      {s.signer || s.problem ? (
        s.verified ? (
          <Tooltip label="The signature matches and the certificate is trusted">
            <Badge color="green" variant="light" tt="none" radius="sm">
              Signed by {s.signer}
            </Badge>
          </Tooltip>
        ) : (
          <Tooltip label={s.problem} multiline maw={320}>
            <Badge color="orange" variant="light" tt="none" radius="sm">
              Signature not verified{s.problem ? `: ${s.problem}` : ''}
            </Badge>
          </Tooltip>
        )
      ) : null}
    </Group>
  )
}

type Decrypted = {
  detail: MessageDetail
  cids: Record<string, string>
  files: { name: string; type: string; size: number; url: string }[]
  signature?: SignatureInfo & { trusted?: boolean; serverProblem?: string }
}

function dataUrl(type: string, content: ArrayBuffer | Uint8Array | string): string {
  const b = typeof content === 'string' ? new TextEncoder().encode(content) : content instanceof Uint8Array ? content : new Uint8Array(content)
  let s = ''
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return `data:${type};base64,${btoa(s)}`
}

/** Decrypts an encrypted message here, with the key in this browser. */
function DecryptedMessage({ id, detail, sender }: { id: number; detail: MessageDetail; sender: string }) {
  const [state, setState] = useState<{ busy: boolean; error?: string; result?: Decrypted }>({ busy: true })
  const check = useApiMutation('mail.CheckCertificates')
  useEffect(() => {
    let live = true
    const urls: string[] = []
    ;(async () => {
      const res = await fetch(`/api/v1/messages/${id}/raw`, { credentials: 'same-origin' })
      if (!res.ok) throw new Error('the message could not be loaded')
      const { entity, signature } = await decryptMessage(await res.arrayBuffer())
      const mail = await PostalMime.parse(Uint8Array.from(entity, (c) => c.charCodeAt(0) & 0xff))
      const cids: Record<string, string> = {}
      const files: Decrypted['files'] = []
      for (const a of mail.attachments) {
        const type = a.mimeType || 'application/octet-stream'
        if (a.contentId && a.disposition !== 'attachment') {
          cids[a.contentId.replace(/^<|>$/g, '')] = dataUrl(type, a.content)
          continue
        }
        const blob = new Blob([typeof a.content === 'string' ? a.content : new Uint8Array(a.content as ArrayBuffer)], { type })
        const url = URL.createObjectURL(blob)
        urls.push(url)
        files.push({ name: a.filename || 'attachment', type, size: blob.size, url })
      }
      let sig: Decrypted['signature'] = signature
      if (signature?.valid) {
        const v = await check.mutateAsync({ chain: signature.chain, from: sender }).catch(() => undefined)
        sig = { ...signature, trusted: v?.trusted, serverProblem: v?.problem }
      }
      const shown: MessageDetail = { ...detail, textBody: mail.text ?? '', htmlBody: mail.html ?? '', attachments: [] }
      if (live) setState({ busy: false, result: { detail: shown, cids, files, signature: sig } })
    })().catch((e: unknown) => live && setState({ busy: false, error: errorText(e) }))
    return () => {
      live = false
      urls.forEach((u) => URL.revokeObjectURL(u))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  if (state.busy)
    return (
      <Center p="xl">
        <Loader size="sm" />
      </Center>
    )
  if (state.error || !state.result)
    return (
      <Alert color="orange" variant="light" title="This message is encrypted">
        <Text size="sm">{state.error}</Text>
        <Anchor component={Link} to="/settings/smime" size="sm">
          Signing and encryption settings
        </Anchor>
      </Alert>
    )
  const { result } = state
  const sig = result.signature
  return (
    <>
      <SignatureBadge
        s={{
          encrypted: true,
          verified: !!sig?.valid && !!sig.trusted,
          signer: sig?.signer ?? '',
          problem: sig ? (sig.problem ?? sig.serverProblem ?? '') : '',
        }}
      />
      <MessageBody id={id} detail={result.detail} sender={sender} cids={result.cids} />
      {result.files.length > 0 && (
        <Group gap="xs" mt="md">
          {result.files.map((f) => (
            <Paper key={f.url} withBorder radius="md" px="sm" py={6}>
              <Group gap="xs" wrap="nowrap">
                <Text size="sm" truncate maw={220}>
                  {f.name}
                </Text>
                <Text size="xs" c="dimmed">
                  {bytes(f.size)}
                </Text>
                <Button component="a" href={f.url} download={f.name} size="compact-xs" variant="default">
                  Save
                </Button>
              </Group>
            </Paper>
          ))}
        </Group>
      )}
    </>
  )
}

/** A message body with its S/MIME state: signature badge, or decryption. */
export function SecureMessage({ id, detail, sender }: { id: number; detail: MessageDetail; sender: string }) {
  const s: SMIMEStatus | undefined = detail.smime
  if (s?.encrypted) return <DecryptedMessage id={id} detail={detail} sender={sender} />
  return (
    <>
      {s?.signed && <SignatureBadge s={s} />}
      <MessageBody id={id} detail={detail} sender={sender} />
      <Attachments id={id} list={detail.attachments} />
    </>
  )
}
