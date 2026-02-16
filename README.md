# Elenko

Node.js web app with **CouchDB**, run via **Docker**. The start page lists CouchDB documents that act as **Profiles** for "Elenko databases" (to be implemented later as sets of CouchDB documents).

## Quick start

```bash
docker compose up --build
```

- **App (start page):** http://localhost:3000  
- **CouchDB:** http://localhost:5984 (user: `admin`, password: `admin`)

## Project layout

| Path | Purpose |
|------|--------|
| `docker-compose.yml` | CouchDB + Node.js app services |
| `Dockerfile` | Node.js app image |
| `server.js` | Express web server; creates DB, index, and serves start page |
| `package.json` | Dependencies: `express`, `nano` (CouchDB client) |

## Profile documents

Profiles are CouchDB documents in the `elenko` database with:

- **`type`:** `"elenko_profile"`

Optional fields shown on the start page: `name`, `description`, `createdAt`.

You can add or edit profile documents in the CouchDB UI (Fauxton at http://localhost:5984/_utils) or via the CouchDB API. Elenko databases (as collections of CouchDB documents) will be built on top of these profiles later.

## Run without Docker

1. Install Node.js 18+ and run CouchDB locally (e.g. on port 5984, user/pass `admin`/`admin`).
2. In the project directory: `npm install` then `npm start`.
3. Open http://localhost:3000.

Environment variables (optional):

- `PORT` – server port (default `3000`)
- `COUCHDB_URL` – e.g. `http://admin:admin@localhost:5984`
- `COUCHDB_DB` – database name (default `elenko`)
