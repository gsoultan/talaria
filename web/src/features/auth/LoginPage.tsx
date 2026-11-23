// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation } from '@connectrpc/connect-query'
import { Alert, Anchor, Box, Button, Checkbox, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@tanstack/react-form'
import { useQueryClient } from '@tanstack/react-query'
import { LogoMark } from '../../components/Logo'
import { AuthService } from '../../gen/talaria/v1/auth_pb'
import { errorText } from '../../lib/errors'

function Envelope({ style }: { style: React.CSSProperties }) {
  return (
    <svg className="t-env" style={style} width="120" height="90" viewBox="0 0 120 90" aria-hidden="true">
      <rect x="4" y="4" width="112" height="82" rx="10" fill="none" stroke="#fff" strokeWidth="6" />
      <path d="M8 10l52 40 52-40" fill="none" stroke="#fff" strokeWidth="6" strokeLinejoin="round" />
    </svg>
  )
}

function BrandPanel() {
  return (
    <Box className="t-brand" visibleFrom="md" style={{ flex: '1 1 50%', display: 'flex', flexDirection: 'column', padding: 48 }}>
      <Envelope style={{ top: '12%', left: '62%' }} />
      <Envelope style={{ top: '58%', left: '8%', animationDelay: '-5s', transform: 'scale(.7)' }} />
      <Envelope style={{ top: '74%', left: '70%', animationDelay: '-9s' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ background: '#fff', borderRadius: 14, padding: 6, display: 'flex' }}>
          <LogoMark size={36} />
        </div>
        <Text fw={700} size="xl">
          {window.location.hostname}
        </Text>
      </div>
      <div style={{ marginTop: 'auto', maxWidth: 460, position: 'relative' }}>
        <Title order={1} c="white" style={{ fontSize: 40, lineHeight: 1.15 }}>
          Your mail, on your own server.
        </Title>
        <Text mt="md" size="lg" style={{ opacity: 0.9 }}>
          Fast webmail that works offline, plus IMAP and POP3 for the apps you already use.
        </Text>
        <Text mt={48} size="sm" style={{ opacity: 0.75 }}>
          Powered by Talaria
        </Text>
      </div>
    </Box>
  )
}

export function LoginPage() {
  const qc = useQueryClient()
  const login = useMutation(AuthService.method.login, {
    onSuccess: () => qc.refetchQueries({ predicate: (q) => (q.queryKey[1] as { methodName?: string } | undefined)?.methodName === 'Me' }),
  })
  const form = useForm({
    defaultValues: { email: '', password: '', remember: true },
    onSubmit: async ({ value }) => {
      await login.mutateAsync(value).catch(() => {})
    },
  })

  return (
    <div style={{ minHeight: '100%', display: 'flex', background: 'var(--t-surface)' }}>
      <BrandPanel />
      <main style={{ flex: '1 1 50%', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <Box w="100%" maw={400}>
          <Box hiddenFrom="md" mb="xl">
            <LogoMark size={40} />
          </Box>
          <Title order={2}>Sign in</Title>
          <Text c="dimmed" mb="xl">
            to {window.location.host}
          </Text>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void form.handleSubmit()
            }}
          >
            <Stack>
              <form.Field
                name="email"
                validators={{ onSubmit: ({ value }) => (/^[^@\s]+@[^@\s]+$/.test(value.trim()) ? undefined : 'Enter your full email address') }}
              >
                {(f) => (
                  <TextInput
                    label="Email address"
                    type="email"
                    autoComplete="username"
                    autoFocus
                    size="md"
                    value={f.state.value}
                    onChange={(e) => f.handleChange(e.currentTarget.value)}
                    onBlur={f.handleBlur}
                    error={f.state.meta.errors[0]}
                  />
                )}
              </form.Field>
              <form.Field name="password" validators={{ onSubmit: ({ value }) => (value ? undefined : 'Enter your password') }}>
                {(f) => (
                  <PasswordInput
                    label="Password"
                    autoComplete="current-password"
                    size="md"
                    value={f.state.value}
                    onChange={(e) => f.handleChange(e.currentTarget.value)}
                    onBlur={f.handleBlur}
                    error={f.state.meta.errors[0]}
                  />
                )}
              </form.Field>
              {login.error && (
                <Alert color="red" variant="light" role="alert">
                  {errorText(login.error)}
                </Alert>
              )}
              <form.Field name="remember">
                {(f) => <Checkbox label="Keep me signed in on this device" checked={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.checked)} />}
              </form.Field>
              <form.Subscribe selector={(s) => s.isSubmitting}>
                {(busy) => (
                  <Button type="submit" size="md" loading={busy} fullWidth>
                    Sign in
                  </Button>
                )}
              </form.Subscribe>
              <Text size="sm" c="dimmed">
                Using Thunderbird or a phone mail app? Use IMAP or POP3 with your email address and password. Server details are in{' '}
                <Anchor size="sm" component="span" c="dimmed" td="underline">
                  Settings
                </Anchor>{' '}
                after you sign in.
              </Text>
            </Stack>
          </form>
        </Box>
      </main>
    </div>
  )
}
