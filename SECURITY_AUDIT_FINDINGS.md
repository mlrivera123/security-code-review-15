# ZITADEL Static Security Audit Findings

## Executive Summary

This static review identified 30 security issues: 3 Critical, 12 High, 8 Medium, and 7 Low. Critical and High findings were corrected. Several Medium and Low findings require persistence or protocol changes and remain open.

No Git history or diff analysis was used.

| Severity | Vulnerability | Primary Location | Fix / Status |
|---|---|---|---|
| Critical | Forgeable user-verification cookie enabled password/passkey enrollment | `apps/login/src/lib/verify-helper.ts` | Fixed with server-secret HMAC, expiry, fingerprint/user binding, and constant-time comparison in `verification-check.ts`. See PoC `CRITICAL-01`. |
| Critical | Empty verification code accepted, enabling invitation takeover | `internal/crypto/code.go` | Fixed by rejecting empty codes and comparing decrypted values in constant time. See PoC `CRITICAL-02`. |
| Critical | Self-management authorized credential creation for arbitrary machine users | `internal/command/permission_checks.go` | Fixed by requiring the target user ID to equal the caller before bypassing permission checks. See PoC `CRITICAL-03`. |
| High | Valid token from one session accepted for another session | `internal/api/authz/session_token.go` | Fixed by binding decrypted tokens to both session ID and token ID and strictly parsing the token structure. |
| High | Resource-scoped permissions treated as global | `internal/api/authz/authorization.go` | Fixed by correctly distinguishing unscoped permissions and enforcing request context IDs. |
| High | Tokenless deletion of foreign sessions | `internal/command/session.go` | Fixed by allowing tokenless deletion only for the caller's own session or callers with `session.delete`. |
| High | Refresh-token scope escalation | `internal/api/oidc/token_refresh.go` | Fixed by requiring requested scopes to be a subset of the original grant. |
| High | Legacy refresh token redeemable through another client | `internal/api/oidc/token_refresh.go` | Fixed with explicit refresh-token/client-ID binding. |
| High | ID token issued to one client exchangeable by another | `internal/api/oidc/token_exchange.go` | Fixed by enforcing `aud` and `azp`, including multi-audience requirements. |
| High | WebAuthn trusted the assertion's self-reported origin | `internal/webauthn/webauthn.go` | Fixed by removing caller-origin input and deriving trusted origins from server request context. |
| High | WebAuthn clone warnings accepted as successful authentication | `internal/command/session_webauhtn.go`, `internal/command/user_human_webauthn.go` | Fixed by rejecting every non-nil WebAuthn validation error. |
| High | Relational passkey path accepted clone warnings | `backend/v3/domain/session_check_passkey.go` | Fixed by failing on every `FinishLoginFn` error, even when credentials are returned. |
| High | U2F physical-presence assertion upgraded to passwordless authentication | `internal/command/session_webauhtn.go` | Fixed by recording the authenticator's actual `UserVerified` flag. |
| High | Updated WebAuthn signature counters were not reloaded | `internal/command/user_human_webauthn_model.go` | Fixed by querying and reducing U2F and passwordless sign-count events. |
| High | Email verification could reuse another user's cookie-selected session | `apps/login/src/lib/server/verify.ts` | Fixed by requiring session user and organization identity to match the verified account. |
| Medium | Legacy unauthenticated AES-CFB tokens accepted despite being disabled | `internal/crypto/aes.go` | Fixed by enforcing the feature flag and trying legacy decryption only when explicitly enabled. |
| Medium | Vulnerable legacy token format enabled by default | `cmd/defaults.yaml` | Fixed by setting `LegacyToken: false`. |
| Medium | Token key rotation failed to decrypt existing JWE tokens | `internal/crypto/aes.go` | Fixed by attempting all configured decryption keys. |
| Medium | Sibling-domain session-cookie fixation | `apps/login/src/lib/cookies.ts` | Fixed by using the `__Host-sessions` cookie name in production. |
| Medium | Password and TOTP lockout occurred one attempt late | `internal/command/user_human_password.go`, `internal/command/user_human_otp.go` | Fixed by locking when failures reach, rather than exceed, the configured limit. |
| Medium | Password-reset codes have no persisted attempt limit | `internal/command/user_human_password.go` | Open. Requires a reset-code failure event/counter, atomic invalidation, and rate limiting. |
| Medium | Successful TOTP values can be replayed within their timestep | `internal/domain/human_otp.go`, `backend/v3/domain/session_check_totp.go` | Open. Requires a persisted accepted-counter high-watermark and atomic greater-than comparison. |
| Medium | Legacy refresh-token migration is non-atomic | `internal/api/oidc/token_refresh.go` | Open. V1 consumption and V2 session creation must occur in one transaction with one-winner enforcement. |
| Low | Biased random verification-code generation | `internal/crypto/code.go` | Fixed using `crypto/rand.Int`, including empty-alphabet validation. |
| Low | Authorization reflection could panic on malformed metadata | `internal/api/authz/authorization.go` | Fixed with request, kind, field, and interface validity checks. |
| Low | Session-token parser accepted trailing fields | `internal/api/authz/session_token.go` | Fixed using strict prefix and delimiter parsing. |
| Low | Invitation resend could invalidate another user's invitation | `internal/command/user_v2_invite.go` | Open. Requires invitation-flow authorization and resend throttling. |
| Low | Logout tokens were replayable and triggered forced logout | `internal/api/oidc/auth_request.go`, `apps/login/src/app/(login)/logout/page.tsx` | Open. Requires short expiry, audience, one-time `jti`, and confirmation or CSRF-protected POST. |
| Low | Master key accepted through process arguments | `cmd/key/masterkey.go`, `deploy/compose/docker-compose*.yml` | Open. Raw argument support should be replaced with restricted secret files or a secret provider. |
| Low | Invalid AES base64 input returned success | `internal/crypto/aes.go` | Fixed by returning the decoding error. |

## Critical PoC Analysis

Detailed local-only reproduction instructions and request templates are available in [`SECURITY_AUDIT_CRITICAL_POC.md`](SECURITY_AUDIT_CRITICAL_POC.md). These PoCs are intended exclusively for isolated, authorized test deployments. The corrected working tree should reject all three attacks.

### CRITICAL-01: Forgeable User-Verification Cookie

**Affected paths:**

- `apps/login/src/lib/verify-helper.ts`
- `apps/login/src/lib/server/password.ts`
- `apps/login/src/lib/server/passkeys.ts`

**Root cause:** The original verification cookie was an unkeyed SHA-256 hash of `userID:fingerprintID`. Both values were supplied by the client, so an attacker could calculate a valid cookie without completing email verification or another authentication step.

**Prerequisites:** The attacker knows the ID of an active human user with no configured authentication methods and can access the login application.

**Attack path:**

1. Select an attacker-controlled fingerprint value.
2. Calculate `SHA256(targetUserID + ":" + fingerprint)`.
3. Set `fingerprintId` and `verificationCheck` cookies to those values.
4. Submit the password-enrollment or passkey-enrollment server action for the target.

**Impact:** The attacker can establish a password or passkey for the victim and authenticate as that account. Depending on the victim's roles, this can lead to instance or organization administration compromise.

**Vulnerable success indicator:** Password or passkey enrollment succeeds without a reset code, authenticated session, or legitimate verification grant.

**Applied fix:** Verification state now uses an HMAC with server-only key material and an authenticated issuance timestamp. Verification is bound to the user and fingerprint, expires after five minutes, and is compared in constant time.

**Post-fix expectation:** A client-generated legacy hash or modified HMAC payload is rejected with a verification-required error.

### CRITICAL-02: Empty Invitation Code Account Takeover

**Affected paths:**

- `internal/crypto/code.go`
- `internal/command/user_v2_invite.go`
- `internal/api/ui/login/invite_user_handler.go`

**Root cause:** The original encrypted-code verifier compared values only when the submitted verification code was non-empty. An empty string therefore bypassed comparison and returned success for any stored invitation code.

**Prerequisites:** The attacker knows the ID of a user with a pending invitation and can obtain a normal CSRF token from the isolated login UI.

**Attack path:**

1. Load the invitation form to establish its CSRF cookie and token.
2. Bypass the browser's `required` attribute by sending a direct HTTP request.
3. Submit the invited user ID, an empty `code`, and an attacker-selected password.
4. The vulnerable command treats the invitation as verified, verifies the email, consumes the invitation, and sets the password.

**Impact:** Complete takeover of pending invited accounts before the legitimate recipient completes onboarding.

**Vulnerable success indicator:** The invitation is consumed and the supplied password is accepted instead of returning an invalid-code error.

**Applied fix:** Empty verification values are rejected before comparison. Decrypted codes are now length-checked and compared with `subtle.ConstantTimeCompare`.

**Post-fix expectation:** An empty code produces an invalid-code response and records an invitation verification failure.

### CRITICAL-03: Cross-User Machine Credential Creation

**Affected paths:**

- `internal/command/permission_checks.go`
- `internal/api/grpc/user/v2/pat.go`
- `internal/api/grpc/user/v2/key.go`
- `internal/api/grpc/user/v2/secret.go`
- `proto/zitadel/user/v2/user_service.proto`

**Root cause:** Enabling self-management caused the user permission callback to return success regardless of whether the target user matched the caller. PAT, key, and secret endpoints enabled self-management while accepting an attacker-controlled target user ID.

**Prerequisites:** The attacker has any authenticated account in the same instance and knows a target machine-user ID. No `user.write` permission over the target is required on vulnerable versions.

**Attack path:**

1. Authenticate as an ordinary user.
2. Send `POST /v2/users/{targetMachineUserID}/pats`, `/keys`, or `/secret`.
3. The vulnerable callback skips the target-user permission check.
4. Capture the returned PAT, private key material, or client secret.
5. Authenticate as the target machine user on the isolated deployment.

**Impact:** Machine-user takeover and inheritance of the target's project, organization, or administrative grants. A privileged service account can turn this into broad tenant compromise.

**Vulnerable success indicator:** An ordinary authenticated user receives HTTP 200 and credential material for a different machine user.

**Applied fix:** Self-management bypass now requires a non-empty target ID equal to the authenticated caller's user ID. Foreign targets proceed through the normal `user.write` permission check.

**Post-fix expectation:** A non-owner without `user.write` receives permission denied and no credential is created.

## PoC Verification Matrix

| PoC | Vulnerable Result | Expected Fixed Result |
|---|---|---|
| `CRITICAL-01` forged verification cookie | Password or passkey enrollment succeeds | Verification is rejected |
| `CRITICAL-02` empty invitation code | Invitation consumed and password set | Invalid-code response |
| `CRITICAL-03` foreign machine credential creation | Target credential returned | Permission denied |

## Verification Status

Regression tests were added for the principal Critical and High fixes, including session binding, refresh scopes, ID-token audiences, WebAuthn origins, WebAuthn counters, clone warnings, verification grants, and cross-user sessions.

Automated execution remains blocked because the workspace lacks the Go toolchain and installed Nx/Node dependencies.
