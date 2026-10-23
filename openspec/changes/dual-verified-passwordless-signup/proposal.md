# Proposal

## Why

The API needs a passwordless account-creation flow that proves control of both an email address and a phone number before persisting a user. Defining this initial behavior provides a secure, testable foundation for the authentication system without requiring a frontend or allowing incomplete registrations to become Postgres users.

## What Changes

- Add passwordless signup using email and phone OTP challenges that may be verified in either order.
- Keep pending registrations and expiring OTP challenges outside the users table; create a Postgres user only after both channels are verified.
- Create completed users with both verified contact methods and active status, then issue access and refresh tokens.
- Add a refresh endpoint that rotates refresh tokens, detects reuse, and revokes the reused token's family.
- Sign access tokens with ES256 and publish public verification keys through a JWKS endpoint for consuming applications.
- Support offline access-token verification while requiring online MuguAuth authorization for sensitive actions that need current account suspension status.
- Keep account active status independent from consent; consent is not a prerequisite for account creation in this flow.
- Do not include password authentication or returning-user sign-in in this initial capability.

## Capabilities

### New Capabilities

- `user-auth`: Passwordless signup requiring verification of both email and phone before account creation.

### Modified Capabilities

None.

## Impact

- Adds signup API behavior across Express routes, controllers, services, and data-access layers.
- Uses Redis for temporary pending-registration and OTP state, and Postgres for finalized users.
- Integrates email and SMS delivery, issues JWT access tokens, and manages opaque rotating refresh-token families according to the existing project guidance.
- Adds `GET /.well-known/jwks.json` and key-rotation behavior for external access-token verification.
- The repository currently contains architecture and OTP guidance but no implementation, package manifest, or existing auth specs; API details and operational safeguards will be defined in the design.
