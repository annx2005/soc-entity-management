# SOC Entity Management Frontend

React + Vite analyst console for the SOC Entity Management MVP.

## Scripts

- `npm run dev`: start Vite on `http://localhost:5173`
- `npm run build`: type-check and create a production build
- `npm run lint`: run `oxlint`

## Environment

- Copy `.env.example` to `.env` for local setup.
- `VITE_API_PROXY_TARGET` controls the dev proxy target for `/api` and `/health`.
- `VITE_API_BASE_URL` lets the frontend call an external API directly when needed.
