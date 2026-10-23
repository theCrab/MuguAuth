# Spec Delta

## Purpose

Defines passwordless account registration that verifies control of both an email address and a phone number before a user account is created. The capability also establishes when completed accounts receive authentication tokens and how refresh-token families are rotated.

## ADDED Requirements

### Requirement: Start registration with both contact methods
The system SHALL accept a valid email address and phone number to begin a passwordless registration, create temporary registration state, and send a distinct one-time code to each contact method. Beginning registration MUST NOT create a user account.

#### Scenario: Registration begins
- **WHEN** a client submits a valid email address and phone number for registration
- **THEN** the system creates temporary registration state and sends one code to the email and another to the phone
- **AND** no user account is created in Postgres

#### Scenario: Invalid contact input
- **WHEN** a client submits an invalid email address or phone number
- **THEN** the system rejects the request and does not create registration state or send codes

### Requirement: Verify email and phone independently
The system SHALL issue cryptographically secure six-digit codes with a five-minute validity window and SHALL permit email and phone verification in either order. A code MUST be accepted only once and only for its corresponding contact method and registration.

#### Scenario: Verify email first
- **WHEN** a client submits the valid email code before verifying the phone
- **THEN** the system marks the email as verified and keeps the registration pending

#### Scenario: Verify phone first
- **WHEN** a client submits the valid phone code before verifying the email
- **THEN** the system marks the phone as verified and keeps the registration pending

#### Scenario: Reject invalid, expired, or previously used code
- **WHEN** a client submits an invalid, expired, or already-consumed code
- **THEN** the system rejects the verification and does not mark that contact method as verified

### Requirement: Create an account only after both verifications
The system SHALL create a user account only after both contact methods for the same registration have been verified. The created account MUST contain both required, unique contact methods and MUST start active.

#### Scenario: Second contact method is verified
- **WHEN** the client successfully verifies the contact method that completes both verifications
- **THEN** the system creates one Postgres user with both verified contact methods and active status
- **AND** the system issues an access token valid for 15 minutes and a refresh token valid for 7 days

#### Scenario: Registration expires before both verifications
- **WHEN** the pending registration expires before both contact methods are verified
- **THEN** the system does not create a user account and the client must begin registration again

#### Scenario: Concurrent completion attempts
- **WHEN** multiple valid requests attempt to complete the same fully verified registration
- **THEN** the system creates no more than one user account for that registration

### Requirement: Rotate refresh tokens once
`POST /auth/refresh` MUST atomically consume the current unused refresh token and return a 15-minute access token and a successor refresh token. Reuse of a previously consumed token MUST revoke the entire family. Refresh tokens MUST be accepted only by MuguAuth authentication endpoints and MUST NOT be treated as access tokens.

#### Scenario: Refresh token rotates successfully
- **WHEN** an active user presents the current unused refresh token to `POST /auth/refresh` before the family expires
- **THEN** the system consumes that token and returns a new 15-minute access token and a successor refresh token

#### Scenario: A consumed refresh token is reused
- **WHEN** a client presents a refresh token that was already consumed by a successful rotation
- **THEN** the system revokes the entire token family and rejects the request
- **AND** no token in that family can be used for another refresh

### Requirement: Keep refresh-token family expiry fixed
The system SHALL set each refresh-token family's absolute expiry to seven days after its creation. Rotation MUST NOT extend the family expiry, and expired or revoked families MUST NOT issue tokens.

#### Scenario: Refresh token family expires
- **WHEN** a client presents a refresh token at or after the family's seven-day absolute expiry
- **THEN** the system rejects the request and issues no tokens

### Requirement: Refuse refresh for inactive accounts
The system MUST NOT issue tokens through refresh for an inactive account.

#### Scenario: Inactive account attempts refresh
- **WHEN** an inactive user presents an otherwise-current refresh token
- **THEN** the system rejects the request and issues no tokens

### Requirement: Publish public keys for access-token verification
The system SHALL expose `GET /.well-known/jwks.json` as a public endpoint containing only public ES256 keys needed to verify currently valid access tokens. Each key MUST have a stable, unique key identifier, and retired keys MUST remain available until tokens signed by them can no longer be valid.

#### Scenario: Consumer retrieves verification keys
- **WHEN** a consumer requests `GET /.well-known/jwks.json`
- **THEN** the system returns a valid JSON Web Key Set containing public verification keys and their identifiers
- **AND** the response contains no private key material

#### Scenario: Signing key rotates
- **WHEN** the system changes its active signing key
- **THEN** it publishes the new public key before issuing tokens that reference it
- **AND** it continues publishing the prior public key while tokens signed by that key may still be valid

### Requirement: Sign access tokens for offline verification
The system SHALL sign access tokens using ES256, include a `kid` identifying the signing key, and provide issuer, audience, and expiration claims for consumers to validate. Refresh tokens MUST be accepted only by MuguAuth authentication endpoints and MUST NOT be treated as access tokens by consuming applications.

#### Scenario: Consumer validates an access token offline
- **WHEN** a consumer has retrieved the corresponding public key from the JWKS endpoint
- **THEN** it can verify the access-token signature and validate issuer, audience, and time-based claims without calling MuguAuth

#### Scenario: Consumer receives an unknown key identifier
- **WHEN** a token references a `kid` absent from the consumer's cached JWKS
- **THEN** the consumer can refresh the JWKS and retry verification once
- **AND** it rejects the token if the key remains unknown

### Requirement: Keep account status independent from consent
The system SHALL use account active status only to represent whether access is allowed, reject protected API requests for inactive users even when their access token is otherwise valid, and SHALL NOT require consent as a prerequisite for account creation or token issuance in this signup flow.

#### Scenario: Signup without consent
- **WHEN** both contact methods are verified and no consent has been recorded
- **THEN** the system may create the active user account and issue tokens
- **AND** the account status does not imply that consent was given

#### Scenario: Suspended user presents a valid access token
- **WHEN** a user whose account is inactive presents an otherwise valid access token to a protected API
- **THEN** the system rejects the request

#### Scenario: Offline consumer validates a token for a suspended user
- **WHEN** an external consumer verifies an unexpired access token offline after its user has been suspended
- **THEN** signature and claim validation alone do not reveal the suspension
- **AND** the consumer routes sensitive actions requiring current account status through a protected MuguAuth API, which rejects the inactive user
