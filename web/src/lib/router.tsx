// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createContext, use, useEffect, useState, type ReactNode } from 'react'

// A small history router: the app has a handful of routes, so a full router
// library would cost more bytes than it saves.

type Location = { path: string; query: URLSearchParams }

const RouterContext = createContext<Location>({ path: '/', query: new URLSearchParams() })

function current(): Location {
  return { path: window.location.pathname, query: new URLSearchParams(window.location.search) }
}

export function navigate(to: string, opts?: { replace?: boolean }) {
  if (to === window.location.pathname + window.location.search) return
  if (opts?.replace) window.history.replaceState(null, '', to)
  else window.history.pushState(null, '', to)
  window.dispatchEvent(new Event('talaria:navigate'))
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [loc, setLoc] = useState(current)
  useEffect(() => {
    const on = () => setLoc(current())
    window.addEventListener('popstate', on)
    window.addEventListener('talaria:navigate', on)
    return () => {
      window.removeEventListener('popstate', on)
      window.removeEventListener('talaria:navigate', on)
    }
  }, [])
  return <RouterContext value={loc}>{children}</RouterContext>
}

export function useLocation(): Location {
  return use(RouterContext)
}

/** match('/mail/:box/:msg?', path) returns the params, or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean)
  const s = path.split('/').filter(Boolean)
  const out: Record<string, string> = {}
  for (let i = 0; i < Math.max(p.length, s.length); i++) {
    const seg = p[i]
    if (seg === undefined) return null
    const optional = seg.endsWith('?')
    const name = seg.replace(/^:/, '').replace(/\?$/, '')
    const val = s[i]
    if (seg.startsWith(':')) {
      if (val === undefined) {
        if (optional) continue
        return null
      }
      out[name] = decodeURIComponent(val)
    } else if (seg !== val) return null
  }
  return out
}

/** Link renders an anchor that navigates without a page load. */
export function Link({ to, children, ...rest }: { to: string; children: ReactNode } & Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  return (
    <a
      href={to}
      {...rest}
      onClick={(e) => {
        rest.onClick?.(e)
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
        e.preventDefault()
        navigate(to)
      }}
    >
      {children}
    </a>
  )
}
