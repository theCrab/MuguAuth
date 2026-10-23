# MuguAuth

Passwordless authentication API using TypeScript, Express, PostgreSQL, Redis, email OTP, SMS OTP, and ES256 access tokens.

## Run locally

1. Install dependencies and copy `.env.example` to `.env`.
2. Set provider credentials and the database/Redis URLs in `.env`.
3. Generate the active ES256 key pair. `JWT_ACTIVE_KID` determines the key filenames:

   ```sh
   mkdir -p "$JWT_KEYS_DIR"
   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
     -out "$JWT_KEYS_DIR/$JWT_ACTIVE_KID.pem"
   openssl pkey -in "$JWT_KEYS_DIR/$JWT_ACTIVE_KID.pem" -pubout \
     -out "$JWT_KEYS_DIR/$JWT_ACTIVE_KID.public.pem"
   chmod 600 "$JWT_KEYS_DIR/$JWT_ACTIVE_KID.pem"
   ```

   Keep private key files out of source control and restrict access to them. The default `./secrets/` directory is ignored by Git.
4. Apply the database migration with `npm run db:migrate`.
5. Start the API with `npm start`.

The API listens on `PORT` (default `3000`). Required environment values are listed in `.env.example`; invalid or missing values stop startup with an explicit configuration error.

## Signup and verification

Signup requires both a valid email and an international phone number. Codes are sent separately and can be verified in either order. No Postgres user is created until both channels are verified.

| Method and path | Request body | Success |
| --- | --- | --- |
| `POST /auth/signup` | `{"email":"person@example.com","phoneNumber":"+14155552671"}` | `201` with a `registrationId` |
| `POST /auth/signup/:registrationId/verify/email` | `{"code":"123456"}` | `200`; the completing verification also returns tokens |
| `POST /auth/signup/:registrationId/verify/phone` | `{"code":"123456"}` | `200`; the completing verification also returns tokens |
| `POST /auth/signup/:registrationId/resend/email` | No body | `202` when sent |
| `POST /auth/signup/:registrationId/resend/phone` | No body | `202` when sent |
| `GET /auth/me` | `Authorization: Bearer <access-token>` | `200` with the current authenticated user's details |

Example verification response before the other channel is verified:

```json
{
  "success": true,
  "data": {
    "verified": true,
    "registrationComplete": false
  }
}
```

The verification that completes signup returns:

```json
{
  "success": true,
  "data": {
    "verified": true,
    "registrationComplete": true,
    "tokens": {
      "accessToken": "<ES256 JWT>",
      "accessTokenExpiresIn": 900,
      "refreshToken": "<opaque refresh token>",
      "refreshTokenExpiresAt": "<ISO-8601 timestamp>"
    }
  }
}
```

Verification codes are six digits, expire after five minutes, and can be used once. Pending registrations expire after 15 minutes. Each channel allows at most three sends, including the initial send, with a 30-second resend cooldown; each code has a bounded number of verification attempts. A delivery-provider failure returns an error and removes the unusable pending registration or challenge.

## Refresh tokens

`POST /auth/refresh` accepts the current refresh token:

```json
{
  "refreshToken": "<opaque refresh token>"
}
```

On success, it returns the same `data.tokens` shape as signup. The access token expires after 15 minutes. The initial refresh-token family expires seven days after signup; rotation returns a successor with that same absolute expiry and does not extend it. A refresh token is single-use. Reusing a consumed token revokes the entire family, so none of its tokens can be refreshed again. Inactive accounts cannot refresh.

Refresh tokens are random opaque credentials. Redis stores only their SHA-256 digests, associated user/family state, and one-use status; it does not store the raw tokens. Refresh tokens are for MuguAuth endpoints only and are not access tokens.

## Access-token verification and JWKS

Access tokens are ES256-signed JWTs with `kid`, `iss`, `aud`, `sub`, `iat`, and `exp` claims. Consumers must pin the accepted algorithm to `ES256` and validate the signature, issuer, audience, and time claims; decoding a JWT without verifying it is not authentication. Consumers can verify ordinary requests offline using:

```text
GET /.well-known/jwks.json
```

The endpoint is public and returns public ES256 keys only. Responses use `Cache-Control: public, max-age=300, must-revalidate`. If a token's `kid` is not in a consumer's cached JWKS, fetch the JWKS once and retry verification; reject the token if the key is still unknown.

To rotate signing keys safely:

1. Generate the new private/public pair using the same filenames, `<new-kid>.pem` and `<new-kid>.public.pem`.
2. Add the new `.public.pem` to `JWT_KEYS_DIR` and verify it appears in the JWKS response before changing `JWT_ACTIVE_KID`.
3. Set `JWT_ACTIVE_KID` to the new key ID and restart the service. New tokens then use the new key; the JWKS continues publishing both keys while both public files are present.
4. Keep the old public key published until at least 15 minutes plus the maximum clock-skew tolerance accepted by consumers after the last token signed with that key. Remove the old public file only after that retention period. The service does not automatically prune key files.
5. Keep private keys protected and remove the old private key from active signing storage when it is no longer needed.

Offline signature and claim validation cannot reflect a later account suspension. Protected MuguAuth routes validate the token and check the current Postgres account status on every request. `GET /auth/me` is a protected identity endpoint; its response is informational and does not authorize a separate downstream action. Any sensitive operation requiring current suspension status must itself be performed by a protected MuguAuth endpoint rather than relying on an offline token claim.

## Error responses

Errors use `{ "success": false, "error": { "message": "...", "code": "..." } }`.

| HTTP status | Error code | Meaning |
| --- | --- | --- |
| `400` | `INVALID_REQUEST`, `INVALID_CONTACT`, `INVALID_CODE`, `INVALID_REGISTRATION_ID`, `INVALID_REFRESH_TOKEN` | Invalid request data or token format |
| `401` | `AUTHENTICATION_REQUIRED`, `INVALID_ACCESS_TOKEN`, `INVALID_REFRESH_TOKEN` | Missing/invalid access token or unknown, expired, revoked, or reused refresh token |
| `403` | `ACCOUNT_INACTIVE` | An inactive account attempted to complete signup or refresh |
| `409` | `CHANNEL_ALREADY_VERIFIED`, `CONTACT_ALREADY_REGISTERED` | Verification channel is already complete or a contact conflicts with another account |
| `410` | `CHALLENGE_EXPIRED`, `REGISTRATION_EXPIRED` | OTP challenge or temporary registration expired |
| `429` | `OTP_ATTEMPT_LIMIT`, `OTP_RESEND_LIMIT` | Verification or resend limit reached |
| `503` | `OTP_DELIVERY_FAILED` | Email or SMS provider could not deliver a code |
| `404` | `NOT_FOUND` | No route matches the request |

Unexpected server errors use HTTP `500` with code `INTERNAL_SERVER_ERROR`.

## Project structure

The application follows a route → controller → service → model structure. Routes and controllers handle HTTP, services coordinate registration, OTP, token, Redis, and provider behavior, and models own Postgres queries. Responses use the standard `{ success, data }` or `{ success, error }` shape.
