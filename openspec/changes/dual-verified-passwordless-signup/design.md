# Design

## Context

The repository is a greenfield API plan: it contains an Express/TypeScript architecture outline and OTP/JWT constraints, but no source, package manifest, database schema, or existing auth capability. The intended layering is routes -> controllers -> services -> models, with a shared response shape and operational errors passed to global middleware.

See [proposal.md](./proposal.md) for motivation and [the user-auth spec](./specs/user-auth/spec.md) for the externally visible contract.

## Goals / Non-Goals

**Goals:**

- Keep all incomplete signup state temporary and out of the Postgres users table.
- Make independently verified email and phone challenges safe against guessing, replay, expiry, and concurrent completion.
- Ensure inactive users cannot use otherwise-valid access tokens on protected API routes.

**Non-Goals:**

- Password authentication, returning-user sign-in, and account recovery.
- A frontend or a consent workflow.
- General session management, including device/session listing or user-managed session revocation.

## Decisions

### Model signup as a temporary Redis registration

`POST /auth/signup` accepts both contact methods, normalizes them, creates a cryptographically random registration identifier, stores a pending registration in Redis, and sends separate codes by email and SMS. It returns the registration identifier for subsequent verification requests. `POST /auth/signup/:registrationId/verify/email` and `/verify/phone` verify each channel independently; either order is valid.

The Redis registration lives for 15 minutes. Each channel has its own cryptographically secure six-digit code with a five-minute validity window. Store a keyed HMAC of each code rather than its plaintext or an unkeyed hash, since the short numeric code space is susceptible to offline guessing. The HMAC key belongs in secret configuration. Do not log codes or include them in API responses. A resend replaces that channel's previous challenge and is rate-limited; invalid attempts are also bounded to prevent online guessing. Exact thresholds should be conservative implementation constants, not client-controlled options.

Redis holds only the pending identifiers, per-channel challenge state, attempt counters, and verification flags. A Redis atomic operation (such as a Lua script) checks expiry and attempt limits, consumes a valid code once, and records that channel as verified. When both flags are true, the service finalizes the account. If finalization encounters a transient database failure, retain enough short-lived completed-registration state to retry finalization without accepting either consumed code again.

The existing OTP guidance mentions clearing an `otp_verified` field on the user row. That storage approach does not fit this flow: no user row exists when the codes are checked. Redis must enforce challenge consumption and verification state instead.

### Persist only fully verified users

Normalize email consistently and store phone numbers in E.164 form before uniqueness checks. The Postgres migration creates required, unique email and phone columns and an `is_active` column defaulting to true. The signup service inserts only after both Redis verification flags are set. Database uniqueness remains authoritative under races; only one matching account may be created, and conflicts must not result in tokens being issued to an unrelated account.

After the insert transaction commits, issue the 15-minute access token and create a refresh-token family with a seven-day absolute expiry. The signup flow does not wait for or imply consent. Consent, if introduced later, needs distinct data and behavior; it must not be inferred from `is_active`.

### Rotate opaque refresh tokens with a fixed family expiry

`POST /auth/refresh` accepts an opaque, cryptographically random refresh token. Redis stores token digests and family state, never plaintext refresh credentials, until the family's absolute expiry. A Redis atomic operation distinguishes a current unused token from a previously consumed token or an unknown token, consumes a current token once, and creates its successor with the original family expiry. Rotation never slides or extends the seven-day lifetime.

If a previously consumed token is presented again, atomically revoke the entire family and reject the request. Unknown credentials do not identify a family and therefore cannot revoke one. Reject expired and revoked families. Before issuing tokens during refresh, check the user's current active status in Postgres; an inactive account receives no tokens. Family revocation prevents further refreshes but does not invalidate already-issued access tokens, which remain usable only until their 15-minute expiry.

### Sign access tokens with ES256 and publish a JWKS

Use ES256 for access-token signing. Keep the EC private signing key in server-only secret storage; never expose it through configuration responses, logs, or JWKS. Each access token carries the active key's stable `kid`, a configured issuer and intended audience, and standard time claims. Consumers pin acceptable algorithms to ES256 and validate signature, issuer, audience, and expiration rather than trusting token headers or decoding claims alone. Refresh tokens are for MuguAuth endpoints and are not authorization credentials for consuming applications.

Expose `GET /.well-known/jwks.json` without authentication. Return public EC verification keys only, with `kid`, `alg: "ES256"`, and `use: "sig"`. Set a bounded cache lifetime so consumers can cache the document without treating it as immutable. During rotation, publish a new public key before signing with it; retain the previous public key until every token signed by it has expired, including the configured clock-skew allowance. Consumers that encounter an unknown `kid` refresh the JWKS once and reject the token if it remains unknown.

### Combine offline verification with online suspension checks

JWKS lets a consumer establish that an access token was signed by MuguAuth and remains within its claims; it does not provide real-time account status or revocation. MuguAuth protected APIs continue checking `is_active` against current Postgres state. Consumers may use offline verification for ordinary low-risk decisions, but sensitive actions that require immediate suspension enforcement must be authorized through a protected MuguAuth API. Do not treat an `is_active` claim embedded in a token as current status.

### Enforce suspension at the protected API boundary

The auth middleware validates the access token and checks the corresponding Postgres user's active state before allowing protected requests. This makes a suspension effective on the next request rather than waiting for an access token to expire. This adds a database read to protected requests; a cache can be considered later only if its invalidation behavior preserves prompt suspension.

### Keep HTTP and business logic separate

Routes delegate to controllers, controllers validate/translate HTTP requests and responses, services coordinate Redis, Postgres, delivery, and tokens, and models own database operations. Responses follow the project's `{ success, data }` / `{ success, error }` shape. Operational failures flow to global error middleware rather than being hidden in controller-level catches.

## Risks / Trade-offs

- [Delivery provider failure can leave a pending signup without a usable code] -> Return an explicit failure, avoid persisting a usable challenge for a message that was not sent, and allow a rate-limited resend while the registration is live.
- [Redis loss or the 15-minute TTL can discard incomplete signup progress] -> Require restarting signup after the pending registration expires; no partial user row needs cleanup.
- [Code guessing or replay could falsely verify a contact] -> Use secure random codes, keyed HMAC storage, five-minute challenge expiry, atomic one-time consumption, bounded attempts, and resend throttling.
- [Concurrent registrations can race on a contact] -> Enforce unique constraints in Postgres and treat the database result as authoritative before issuing tokens.
- [Refresh-token theft or replay can extend unauthorized access] -> Use opaque random credentials, store only token digests, atomically rotate each token once, revoke the family on reuse, and preserve a fixed seven-day absolute expiry.
- [Checking account status on each protected request adds database load] -> Prefer correctness and prompt suspension for the initial API; measure before considering a cache.
- [A consumer may cache stale JWKS data or mishandle a key rotation] -> Publish keys before use, overlap old and new public keys, bound HTTP caching, and require one refresh for an unknown `kid`.
- [Offline signature validation cannot reflect a later suspension] -> Route sensitive operations through protected MuguAuth APIs that check current account state.
- [Signing-key compromise permits token forgery] -> Restrict access to the ES256 private key, support key rotation, and keep private material out of JWKS and logs.
- [A cross-store failure can occur between Redis and Postgres] -> Keep finalization retryable and idempotent, rely on database uniqueness, and never issue tokens before a successful account commit.

## Migration Plan

This is a greenfield capability with no existing application data to migrate. Add the initial users schema and Redis/Postgres configuration as part of implementation. Rollback before deployment requires no data conversion; after signup data exists, do not drop the users table as a routine rollback.
