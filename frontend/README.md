# SOC Entity Management Frontend

React + Vite analyst console for the SOC Entity Management MVP.

## Scripts

- `npm run dev`: start Vite on `http://localhost:5173`
- `npm run build`: type-check and create a production build
- `npm run lint`: run `oxlint`

The dev server proxies `/api` and `/health` to `http://localhost:8000` by default. In Docker Compose, `VITE_API_PROXY_TARGET` points the proxy to the backend service.
