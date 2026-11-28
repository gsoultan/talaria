// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

const units = ['B', 'KB', 'MB', 'GB', 'TB']

export function bytes(n: number): string {
  let v = Number(n)
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

const time = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' })
const dayMonth = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' })
const full = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const yearly = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })

/** Short list date: time today, weekday this week, date otherwise. */
export function listDate(unix: number): string {
  const d = new Date(Number(unix) * 1000)
  const now = new Date()
  if (d.toDateString() === now.toDateString()) return time.format(d)
  const yesterday = new Date(now)
  yesterday.setDate(now.getDate() - 1)
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday'
  if (d.getFullYear() === now.getFullYear()) return dayMonth.format(d)
  return yearly.format(d)
}

export function fullDate(unix: number): string {
  return full.format(new Date(Number(unix) * 1000))
}

export function initials(name: string, addr = ''): string {
  const src = (name || addr.split('@')[0] || '?').trim()
  const parts = src.split(/[\s._-]+/).filter(Boolean)
  const a = parts[0]?.[0] ?? '?'
  const b = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : ''
  return (a + b).toUpperCase()
}

export function plural(n: number, one: string, many = one + 's'): string {
  const v = Number(n)
  return `${v.toLocaleString()} ${v === 1 ? one : many}`
}

/** Splits "Ana <ana@x>, bob@y" into addresses. */
export function splitAddresses(s: string): string[] {
  return s
    .split(/[,;\n]/)
    .map((p) => p.trim())
    .filter(Boolean)
}

const palette = ['blue', 'grape', 'teal', 'orange', 'pink', 'indigo', 'cyan', 'lime', 'violet']

/** A stable avatar colour per sender. */
export function avatarColor(key: string): string {
  let h = 0
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) | 0
  return palette[Math.abs(h) % palette.length]!
}
