# backend-rust

Rust port of the BunJS login and authentication backend (`smartfarm_db` / MySQL). Axum HTTP server with MySQL and SQLite storage, JWT access tokens, rotating refresh tokens, and rate-limited login.

## Run

```bash
JWT_SECRET="replace-with-a-long-random-secret" cargo run
```

## Configuration

Environment variables (local `.env` is loaded but real environment variables win):

- `HOST` (default `0.0.0.0`), `PORT` (default `8080`)
- `DATABASE_URL` — `mysql://user:password@host:3306/smartfarm_db` or `sqlite://auth.db`
- `DB_DRIVER` / `DB_CONNECTION` — `mysql` (default) or `sqlite`
- `DB_PATH` — SQLite path (default `auth.db`)
- `MYSQL_HOST` / `DB_HOST`, `MYSQL_PORT` / `DB_PORT`, `MYSQL_USER` / `DB_USER` / `DB_USERNAME`, `MYSQL_PASSWORD` / `DB_PASSWORD`, `MYSQL_DB` / `DB_DATABASE` / `DB_NAME`
- `JWT_SECRET` — set a strong persistent secret in production; a random ephemeral one is generated otherwise
- `ACCESS_TOKEN_TTL_SEC` (default `900`), `REFRESH_TOKEN_TTL_SEC` (default `604800`)
- `PBKDF2_ITERATIONS` (default `210000`)
- `LOGIN_MAX_ATTEMPTS` (default `10`), `LOGIN_RATE_WINDOW_SEC` (default `60`)

## Tests

```bash
cargo test
```

## API endpoints

- `GET /`, `GET /health` (and `/healthz`)
- `POST /api/auth/register` (alias `/auth/register`)
- `POST /api/auth/login` (alias `/auth/login`)
- `POST /api/auth/refresh` (alias `/auth/refresh`)
- `POST /api/auth/logout` (alias `/auth/logout`)
- `POST /api/auth/logout-all` (alias `/auth/logout-all`) — Bearer token required
- `GET /api/auth/me` (alias `/auth/me`) — Bearer token required
- `POST /api/auth/change-password` (alias `/auth/change-password`) — Bearer token required

# backend-rust
