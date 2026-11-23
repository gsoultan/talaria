// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import babel from '@rolldown/plugin-babel'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'

// The Go server serves the API and this build from one origin, so the dev
// server proxies API calls to it.
const apiTarget = process.env.TALARIA_API ?? 'http://localhost:8080'

export default defineConfig({
  plugins: [
    react(),
    // React Compiler: automatic memoization, no manual useMemo/useCallback.
    babel({ presets: [reactCompilerPreset()] }),
    VitePWA({
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.ts',
      registerType: 'prompt',
      injectRegister: false,
      manifest: {
        name: 'Talaria Mail',
        short_name: 'Talaria',
        description: 'Fast, lightweight webmail',
        theme_color: '#1c7ed6',
        background_color: '#ffffff',
        display: 'standalone',
        start_url: '/',
        icons: [
          { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' },
        ],
      },
      injectManifest: {
        globPatterns: ['**/*.{js,css,html,svg,woff2}'],
        // Only Latin fonts are precached; other scripts load when a page needs them.
        globIgnores: ['**/inter-{cyrillic,cyrillic-ext,greek,greek-ext,vietnamese}-*.woff2'],
      },
    }),
  ],
  build: {
    target: 'es2023',
    cssCodeSplit: true,
    sourcemap: false,
    rolldownOptions: {
      output: {
        // Keep the big, rarely-changing libraries in their own cached chunks.
        advancedChunks: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: 'mantine', test: /node_modules[\\/]@mantine[\\/]/ },
            { name: 'data', test: /node_modules[\\/](@tanstack|@connectrpc|@bufbuild)[\\/]/ },
          ],
        },
      },
    },
  },
  worker: { format: 'es' },
  server: {
    proxy: {
      '/talaria.v1.': { target: apiTarget, changeOrigin: true },
      '/api/': { target: apiTarget, changeOrigin: true },
    },
  },
})
