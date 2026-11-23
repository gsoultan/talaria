// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Group, Modal, Text, type ButtonProps } from '@mantine/core'
import { useState, type ReactNode } from 'react'

/** A button that asks before doing something that cannot be undone. */
export function ConfirmButton({ label, title, body, confirm, onConfirm, ...rest }: { label: ReactNode; title: string; body: ReactNode; confirm: string; onConfirm: () => Promise<unknown> | void } & Omit<ButtonProps, 'children'>) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  return (
    <>
      <Button {...rest} onClick={() => setOpen(true)}>
        {label}
      </Button>
      <Modal opened={open} onClose={() => setOpen(false)} title={title} centered>
        <Text size="sm">{body}</Text>
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            color="red"
            loading={busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onConfirm()
                setOpen(false)
              } finally {
                setBusy(false)
              }
            }}
          >
            {confirm}
          </Button>
        </Group>
      </Modal>
    </>
  )
}
