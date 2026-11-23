// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from '@connectrpc/connect-query'
import { Badge, Card, Group, Loader, Text } from '@mantine/core'
import { SystemService } from '../gen/talaria/v1/system_pb'

function formatBytes(n: bigint): string {
  const v = Number(n)
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(0)} KiB`
  return `${(v / 1024 / 1024).toFixed(1)} MiB`
}

export function ServerInfo() {
  const { data, isPending, error } = useQuery(SystemService.method.getInfo, {})
  if (isPending) return <Loader size="sm" />
  if (error) return <Text c="red">Server unreachable: {error.message}</Text>
  return (
    <Card withBorder padding="lg" radius="md">
      <Group justify="space-between" mb="xs">
        <Text fw={600}>Talaria {data.version}</Text>
        <Badge variant="light">{data.goVersion}</Badge>
      </Group>
      <Text size="sm" c="dimmed">
        Heap {formatBytes(data.heapBytes)} of {formatBytes(data.memoryLimitBytes)} limit, up {data.uptimeSeconds.toString()}s
      </Text>
    </Card>
  )
}
