# Elenko

Node.js web app with **CouchDB**, run via **Docker**. The start page lists CouchDB documents that act as **Profiles** for "Elenko databases" (to be implemented later as sets of CouchDB documents).

## Quick start

```shell
docker compose up --build
```

- **App (start page):** `http://localhost:3000`
- **CouchDB:** `http://localhost:5984` (user: `admin`, password: `admin`)

## Project layout

| Path               | Purpose                                                      |
| ------------------ | ------------------------------------------------------------ |
| `docker-compose.yml` | CouchDB + Node.js app services                             |
| `Dockerfile`       | Node.js app image                                            |
| `server.js`        | Express web server; creates DB, indexes, auth, and serves UI |
| `package.json`     | Dependencies: `express`, `express-session`, `nano` (CouchDB client) |

## Profile documents

Profiles are CouchDB documents in the `elenko` database with:

- **`type`**: `"elenko_profile"`

Optional fields shown on the start page: `name`, `description`, `createdAt`.

You can add or edit profile documents in the CouchDB UI (Fauxton at `http://localhost:5984/_utils`) or via the CouchDB API. Elenko databases (as collections of CouchDB documents) are built on top of these profiles using **entries** (CouchDB documents with `type: "elenko_record"`).

## Authentication & roles

The application is protected by a simple login system with **users stored in CouchDB**:

- On first start, an **admin user** is seeded:
  - **Username**: `admin`
  - **Password**: `admin`
  - **Role**: `admin`
- Passwords are stored as PBKDF2 hashes with a per-user salt (not in plain text).

### Roles

- **admin**
  - Full access to the application.
  - Can **view/edit/delete profiles**.
  - Can **view all documents**, manage **pending deletions**, and use the **“Marked for deletion”** flows.
  - Can **create new users** (admin or user) and **change own password**.

- **user**
  - Can **see the list of profiles** and open a profile’s **Elenko database** page.
  - Can **view, create, and edit entries** (CouchDB documents with `type: "elenko_record"`).
  - **Cannot** view/edit/delete profiles.
  - **Cannot** see “Marked for deletion”, “All documents”, or the **create user** page.

### Login URLs

- **Login**: `GET /login`  
  - Form fields: `username`, `password`
- **Logout**: `GET /logout`
- **Change password** (logged-in users): `GET /account/change-password`
- **Create user** (admins only): `GET /account/users/create`

If you access any app page without being logged in, an **“Login required”** error page is shown with a link to `/login`.

## Run without Docker

1. Install Node.js 18+ and run CouchDB locally (e.g. on port 5984, user/pass `admin`/`admin`).
2. In the project directory:

   ```shell
   npm install
   npm start
   ```

3. Open `http://localhost:3000`.

Environment variables (optional):

- `PORT` – server port (default `3000`)
- `COUCHDB_URL` – e.g. `http://admin:admin@localhost:5984`
- `COUCHDB_DB` – database name (default `elenko`)

