# Secure Messaging — Frontend

Professional React + TypeScript frontend for the Secure Messaging backend
(deployed at `https://secure-messaging-backend-g7v0.onrender.com`).

This repository contains **only** the frontend. The backend lives in a
separate repository (`capstonebackend`) and is not modified from here.

## Current status

- **Branch:** `develop`
- **Phase:** 0 — foundation only
- **Implemented:** Vite + React + TypeScript shell, React Router with
  placeholder routes, application layout, typed environment configuration.
- **Not implemented yet:** authentication, cryptography, WebSocket transport,
  IndexedDB persistence, chat functionality, business logic.

Phases will add these features incrementally. Do not expect any of them to
work today.

## Tech stack

- React 18
- TypeScript (strict)
- Vite 5
- React Router 6

## Getting started

```bash
npm install
npm run dev
```

The dev server runs on `http://localhost:5173` by default.

## Scripts

| Command | What it does |
|---------|--------------|
| `npm run dev` | Start the Vite dev server with HMR. |
| `npm run build` | Type-check (`tsc --noEmit`) and produce a production build in `dist/`. |
| `npm run preview` | Serve the built `dist/` locally. |
| `npm run typecheck` | Run `tsc --noEmit` only. |

## Environment configuration

Copy `.env.example` to `.env` and adjust the values for your environment.

Only variables prefixed with `VITE_` are bundled into the client and **must
never contain secrets**. This application has no API keys and no client-side
secrets.

## Routes (placeholders)

| Path | Purpose |
|------|---------|
| `/` | Landing page |
| `/login` | Sign in (placeholder) |
| `/register` | Create account (placeholder) |
| `/chat` | Chat experience (placeholder) |
| `/settings` | Settings (placeholder) |
| `/404` | Not found |

## Project layout

```
src/
  api/         # HTTP client (future)
  auth/        # Authentication (future)
  components/  # Reusable UI components
  config/      # Typed environment configuration
  crypto/      # Cryptographic primitives (future)
  hooks/       # Reusable React hooks (future)
  pages/       # Page-level components
  realtime/    # WebSocket transport (future)
  routes/      # Router configuration
  store/       # Client state stores (future)
  styles/      # Global CSS
  types/       # Shared TypeScript types (future)
  utils/       # Cross-cutting helpers (future)
  App.tsx
  main.tsx
```

## License

Capstone project. See the backend repository for the system-level license.