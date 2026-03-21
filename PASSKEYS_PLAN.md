# FIDO2 / Passkey integration plan for Calibre-Web

This document maps the current authentication architecture and proposes a concrete, low-risk plan to add passkey support.

## What exists today (repo exploration)

### Authentication entry points

- Username/password login is handled in `cps/web.py` via `login()` (GET) and `login_post()` (POST).
- Login UI is rendered by `cps/templates/login.html`.
- Additional auth methods already supported:
  - LDAP (in `login_post()` branch in `cps/web.py`)
  - OAuth (`cps/oauth_bb.py` + social buttons rendered from `login.html`)
  - Magic-link remote login (`cps/remotelogin.py`)

### User/session storage

- User records are in `ub.User` (SQLAlchemy model in `cps/ub.py`).
- Sessions are handled by Flask-Login + app-specific cleanup in logout path (`cps/web.py`).
- DB migrations are currently done in code (no Alembic): `migrate_Database()` in `cps/ub.py`.

### App wiring

- Blueprints are registered in `cps/main.py`.
- New auth endpoints should follow the existing blueprint approach and be added from `main.py`.

---

## Proposed passkey architecture

### 1) Add a new persistence model

Create a new table in `cps/ub.py`, for example `WebAuthnCredential`:

- `id` (PK)
- `user_id` (FK -> `user.id`, indexed)
- `credential_id` (base64url string, unique)
- `public_key` (credential public key bytes, encoded)
- `sign_count` (integer, default 0)
- `aaguid` (optional)
- `transports` (optional JSON/string)
- `created_at`, `last_used_at`
- `nickname` (optional friendly name)
- `is_active` (soft-disable support)

Add relation on `User`:

- `webauthn_credentials = relationship('WebAuthnCredential', backref='user', lazy='dynamic')`

Migration approach (consistent with current project style):

- In `migrate_Database()` call a new helper (e.g. `migrate_webauthn_table`) that creates the table if missing.

### 2) Add a dedicated blueprint for WebAuthn

Create `cps/webauthn.py` with endpoints grouped in two flows:

#### A. Registration (while user is logged in)

- `POST /webauthn/register/options`
  - Generates challenge + RP/user parameters.
  - Stores challenge in server-side session (short TTL).
- `POST /webauthn/register/verify`
  - Verifies attestation response.
  - Persists credential to `WebAuthnCredential`.

#### B. Authentication (from login screen)

- `POST /webauthn/auth/options`
  - Generates challenge.
  - Option 1: allow discoverable credentials (username-less).
  - Option 2: require username then restrict `allowCredentials`.
- `POST /webauthn/auth/verify`
  - Verifies assertion.
  - Looks up credential, validates challenge/RP/origin/sign counter.
  - Calls existing `handle_login_user(...)` helper from `cps/web.py` to preserve current login behavior.

Register the blueprint in `cps/main.py`.

### 3) Add login + profile UI changes

- Login page (`cps/templates/login.html`):
  - Add a `Sign in with passkey` button.
  - Add JS that calls `/webauthn/auth/options` then `navigator.credentials.get(...)`, then `/verify`.
- Profile page (`cps/templates/user_edit.html` and handler in `cps/web.py`):
  - Add a passkey management section:
    - register new passkey
    - list existing passkeys
    - revoke passkey

### 4) Security controls (must-have)

- Verify RP ID and origin strictly (config-driven for reverse proxy setups).
- Store and validate challenge server-side with expiry and one-time use.
- Validate and update signature counter (`sign_count`) to detect cloned credentials.
- Reuse existing rate limiting pattern (`limiter.limit(...)`) on passkey auth endpoints.
- Log auth events in the same style as existing login code (without leaking sensitive blobs).

### 5) Config additions

Add config keys (names tentative):

- `config_webauthn_enabled` (bool)
- `config_webauthn_rp_id`
- `config_webauthn_rp_name`
- `config_webauthn_origin` (or list)
- `config_webauthn_user_verification` (`preferred`/`required`/`discouraged`)

Ensure passkeys can be disabled globally.

### 6) Dependency recommendation

Use a maintained WebAuthn server library for Python (instead of custom crypto):

- Suggested: `webauthn` (duo-labs project lineage) or equivalent actively maintained implementation.

Keep all binary data encoded as base64url when moving between JS and Python.

---

## Incremental delivery plan

### Phase 1 (foundation)

- Add model + migration helper.
- Add config flags.
- Add skeleton blueprint with options/verify endpoints returning feature-disabled when off.

### Phase 2 (registration UX)

- Logged-in user can register a passkey.
- Store credential and render list in profile.

### Phase 3 (login UX)

- Add `Sign in with passkey` from login page.
- Verify assertion and complete Flask login.

### Phase 4 (hardening)

- Add rate limits, audit logs, revocation UX polish.
- Add tests for challenge replay, bad origin/RP ID, sign counter rollback.

---

## Test plan to add with implementation

- Unit tests for challenge lifecycle and verifier wrappers.
- Endpoint tests:
  - register options/verify happy path
  - auth options/verify happy path
  - invalid origin
  - replayed challenge
  - unknown credential
- Integration sanity test: password and OAuth/LDAP flows still work.

---

## Notes for compatibility

- Passkeys should coexist with password login (no forced migration).
- Admins should be able to recover accounts by revoking credentials.
- Keep localization impact small initially (English strings first, then translation pass).
