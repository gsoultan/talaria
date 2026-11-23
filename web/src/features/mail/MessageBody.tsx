// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Button, Group, Text } from '@mantine/core'
import { useEffect, useRef, useState } from 'react'
import type { MessageDetail } from '../../gen/talaria/v1/mail_pb'
import { prepareHtml } from '../../lib/mimeWorker'

// Remote images are blocked until the person allows them, per sender.
const allowKey = 'talaria.remote-images'

function allowedSenders(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(allowKey) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function allowSender(addr: string) {
  try {
    const s = allowedSenders()
    s.add(addr.toLowerCase())
    localStorage.setItem(allowKey, JSON.stringify([...s].slice(-500)))
  } catch {
    // Storage unavailable: images stay allowed for this view only.
  }
}

const linkRe = /\b(https?:\/\/[^\s<>"')]+)/g

function PlainText({ text }: { text: string }) {
  // Links become clickable; everything else stays text, so nothing in the
  // message can inject markup.
  const parts = text.split(linkRe)
  return (
    <Text component="div" size="sm" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', lineHeight: 1.6 }}>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <a key={i} href={p} target="_blank" rel="noopener noreferrer nofollow">
            {p}
          </a>
        ) : (
          p
        ),
      )}
    </Text>
  )
}

/** Renders HTML mail in a sandboxed frame: no scripts, forms or navigation. */
function HtmlFrame({ html }: { html: string }) {
  const ref = useRef<HTMLIFrameElement>(null)
  const [height, setHeight] = useState(200)
  useEffect(() => {
    const f = ref.current
    if (!f) return
    let ro: ResizeObserver | undefined
    const fit = () => {
      const doc = f.contentDocument
      if (!doc?.body) return
      setHeight(Math.max(doc.documentElement.scrollHeight, doc.body.scrollHeight) + 8)
      ro?.disconnect()
      ro = new ResizeObserver(() => setHeight(Math.max(doc.documentElement.scrollHeight, doc.body.scrollHeight) + 8))
      ro.observe(doc.body)
    }
    f.addEventListener('load', fit)
    return () => {
      f.removeEventListener('load', fit)
      ro?.disconnect()
    }
  }, [html])
  return (
    <iframe
      ref={ref}
      title="Message"
      // allow-same-origin only lets this page measure the frame; without
      // allow-scripts nothing inside can run.
      sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
      referrerPolicy="no-referrer"
      srcDoc={html}
      style={{ width: '100%', height, border: 0, display: 'block', colorScheme: 'light', background: '#fff', borderRadius: 8 }}
    />
  )
}

export function MessageBody({ id, detail, sender }: { id: bigint; detail: MessageDetail; sender: string }) {
  const [allow, setAllow] = useState(() => allowedSenders().has(sender.toLowerCase()))
  const [prepared, setPrepared] = useState<{ html: string; hasRemote: boolean } | null>(null)

  useEffect(() => {
    if (!detail.htmlBody) return
    const cids: Record<string, string> = {}
    for (const a of detail.attachments) if (a.contentId) cids[a.contentId] = `/api/messages/${id}/parts/${a.part}?inline=1`
    let live = true
    void prepareHtml(detail.htmlBody, cids, allow).then((r) => live && setPrepared(r))
    return () => {
      live = false
    }
  }, [id, detail, allow])

  if (!detail.htmlBody) return <PlainText text={detail.textBody} />
  return (
    <>
      {prepared?.hasRemote && !allow && (
        <Alert variant="light" color="gray" mb="sm" p="xs">
          <Group justify="space-between" gap="xs">
            <Text size="sm">Remote images are blocked to protect your privacy.</Text>
            <Group gap="xs">
              <Button size="compact-sm" variant="default" onClick={() => setAllow(true)}>
                Show images
              </Button>
              <Button
                size="compact-sm"
                variant="subtle"
                onClick={() => {
                  allowSender(sender)
                  setAllow(true)
                }}
              >
                Always from this sender
              </Button>
            </Group>
          </Group>
        </Alert>
      )}
      {prepared ? <HtmlFrame html={prepared.html} /> : <div style={{ height: 200 }} />}
    </>
  )
}
