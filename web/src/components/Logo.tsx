// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 512 512" aria-hidden="true">
      <rect width="512" height="512" rx="96" fill="#1971c2" />
      <path d="M96 160h320v192H96z M96 160l160 112 160-112" fill="none" stroke="#fff" strokeWidth="32" strokeLinejoin="round" />
    </svg>
  )
}
