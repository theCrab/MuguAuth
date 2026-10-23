# Tasks

## 1. API and persistence foundation

- [x] 1.1 Bootstrap the TypeScript/Express application and test/build scripts using the documented route-controller-service-model structure; verify the TypeScript build and a basic app startup test pass.
- [x] 1.2 Add validated Postgres, Redis, email, SMS, and ES256 JWT signing configuration with an `.env.example`; test missing or invalid required configuration produces an explicit startup error and verify the example documents every required variable without exposing private-key material.
- [x] 1.3 Add the initial Postgres migration for users with required normalized email and E.164 phone fields, unique constraints, and `is_active` defaulting to true; verify migration and rollback behavior against a test database.

## 2. Temporary registration and OTP delivery

- [x] 2.1 Implement contact validation and normalization plus creation of a temporary Redis registration with a 15-minute lifetime; verify valid/invalid email and phone cases and confirm no Postgres user is created at signup start.
- [x] 2.2 Implement independent secure six-digit email and phone challenges with keyed-HMAC storage, five-minute expiry, one-time atomic consumption, bounded attempts, and rate-limited resends; test expiry, invalid attempts, replay rejection, and Redis concurrency.
- [x] 2.3 Integrate email and SMS delivery adapters for signup codes with explicit provider-failure handling; test that delivery failures return the standard error response and do not leave an unusable active challenge.

## 3. Verification and account finalization

- [x] 3.1 Implement signup and per-channel verification routes/controllers with the standard response and error shape; test validation failures and successful verification in both email-first and phone-first order.
- [x] 3.2 Finalize the Postgres user only after both channels verify, handling unique-contact conflicts and concurrent/retried completion idempotently; test that partial verification creates no user and competing completion creates at most one.
- [x] 3.3 Issue access tokens and create the initial refresh-token family only after committed account creation, with 15-minute access-token and fixed seven-day family lifetimes; test token issuance timing and expirations.
- [x] 3.4 Implement `POST /auth/refresh` with opaque Redis-backed refresh tokens, atomic one-time rotation, whole-family revocation on reuse, inactive-account rejection, and fixed absolute expiry; test successful rotation, concurrent/replayed redemption, revocation, and expiry.
- [x] 3.5 Sign access tokens with ES256 and include `kid`, issuer, audience, and time claims; test signature verification, claim validation, and rejection of tokens signed with an unsupported algorithm.
- [x] 3.6 Implement public `GET /.well-known/jwks.json` with only public ES256 signing keys and bounded cache headers; test JWKS shape, key identifiers, and absence of private key material.
- [x] 3.7 Implement safe key rotation that publishes new keys before use and retains old public keys through token expiry and clock skew; test consumer key refresh for unknown `kid` and verification across rotation.
- [x] 3.8 Document the signup, verification, and refresh API contracts, JWKS discovery, consumer token-validation requirements, token and family expiration, resend, replay, and error behavior in the project README; verify examples match the implemented routes and standard response shape.

## 4. Protected API access control

- [x] 4.1 Implement JWT authentication middleware that checks the user's current active status before allowing protected requests; test active users pass and inactive users are rejected even with an otherwise-valid token.
- [x] 4.2 Ensure sensitive operations that require current suspension status are authorized through protected MuguAuth APIs rather than relying on offline token claims; test a suspended user's request is rejected.

## 5. End-to-end verification

- [x] 5.1 Add an end-to-end signup test covering both channel orders, temporary state expiry, final user creation, access-token response, offline JWKS verification, and inactive-user rejection at protected APIs; run the focused integration suite with Postgres and Redis test services.
