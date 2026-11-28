// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Button, Center, Code, Group, Image, Loader, Modal, ScrollArea, Table, Text } from '@mantine/core'
import { type Attachment, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { bytes } from '../../lib/format'

/** A safe preview of an attachment: its text, the files in an archive, or
 * an image drawn again on the server. Nothing in the file runs. */
export function AttachmentPreview({ id, a, onClose }: { id: number; a: Attachment; onClose: () => void }) {
  const q = useApiQuery('mail.GetAttachmentPreview', { id, part: a.part }, { staleTime: 10 * 60_000 })
  const p = q.data
  const url = `/api/v1/messages/${id}/parts/${a.part}`
  const dangerous = (p?.findings.length ?? 0) > 0
  return (
    <Modal opened onClose={onClose} size="xl" title={<Text fw={600} truncate maw={600}>{a.filename || 'attachment'}</Text>}>
      {q.isPending && (
        <Center h={200}>
          <Loader size="sm" />
        </Center>
      )}
      {q.error && <Alert color="red">{errorText(q.error)}</Alert>}
      {p && (
        <>
          {dangerous && (
            <Alert color="red" variant="light" mb="sm" title="This file looks dangerous">
              <Text size="sm">{p.findings.join('; ')}. Do not open it unless you are sure who sent it and why.</Text>
            </Alert>
          )}
          {!dangerous && a.risky && (
            <Alert color="orange" variant="light" mb="sm" p="xs">
              <Text size="sm">Files of this type can carry macros or malware. This preview shows only what is in it; nothing runs.</Text>
            </Alert>
          )}
          {p.note && (
            <Text size="sm" c="dimmed" mb="sm">
              {p.note}
            </Text>
          )}
          {p.kind === 'image' && (
            <Center bg="gray.1" p="sm" style={{ borderRadius: 8 }}>
              <Image src={`${url}/image`} alt={a.filename} mah="65vh" fit="contain" w="auto" />
            </Center>
          )}
          {p.kind === 'text' && (
            <ScrollArea.Autosize mah="60vh" type="auto">
              <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13 }}>
                {p.text}
              </Code>
            </ScrollArea.Autosize>
          )}
          {p.kind === 'list' && (
            <ScrollArea.Autosize mah="60vh" type="auto">
              <Table fz="sm">
                <Table.Tbody>
                  {p.items.map((it) => (
                    <Table.Tr key={it.name}>
                      <Table.Td style={{ wordBreak: 'break-all' }}>{it.name}</Table.Td>
                      <Table.Td ta="right" c="dimmed">
                        {it.encrypted ? 'password protected · ' : ''}
                        {bytes(it.size)}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea.Autosize>
          )}
          {p.truncated && (
            <Text size="xs" c="dimmed" mt="xs">
              Only the start is shown.
            </Text>
          )}
          <Group justify="space-between" mt="md" wrap="wrap">
            <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>
              {bytes(p.size)} · SHA-256 {p.sha256}
            </Text>
            {!dangerous && (
              <Button component="a" href={url} download={a.filename || true} variant={a.risky ? 'default' : 'filled'}>
                Download
              </Button>
            )}
          </Group>
        </>
      )}
    </Modal>
  )
}
