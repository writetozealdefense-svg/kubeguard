# KubeGuard Dashboard — Web

React 18 + TypeScript + Vite single-page app for the KubeGuard dashboard BFF.

## Develop

```bash
npm ci          # install pinned deps (regenerates correct bin permissions)
npm run dev     # vite dev server
npm run build   # tsc -b && vite build
npm run lint    # eslint, 0 warnings
npm run test    # vitest
npm run e2e     # playwright (real Chromium)
```

Point the app at a running backend, or set `VITE_USE_MOCK=1` to render the
cluster-aware mock used by the e2e suite. For SSO, build with
`VITE_OIDC_AUTHORIZE_URL` set.

## Troubleshooting

**`tsc: permission denied` / `EACCES` on `node_modules/.bin`** — some
archive-extraction and file-sync paths drop the executable bit on the
`node_modules/.bin` symlinks. `npm run build` runs a `prebuild` step that
restores those bits automatically (cross-platform, safe to re-run). If you hit
it outside of `build`, either re-run `npm ci` or restore the bits manually:

```bash
chmod -R +x node_modules/.bin
```

CI uses `npm ci`, which always installs with the correct permissions, so this
only affects some local checkouts.
