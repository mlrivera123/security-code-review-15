import crypto from "crypto";
import { readFileSync } from "fs";

const USER_VERIFICATION_MAX_AGE_MS = 5 * 60 * 1000;

function userVerificationSecret(): string {
  const secret =
    process.env.ZITADEL_LOGIN_VERIFICATION_SECRET ??
    process.env.SYSTEM_USER_PRIVATE_KEY ??
    process.env.ZITADEL_SERVICE_USER_TOKEN;
  if (secret) {
    return secret;
  }

  const secretFile = process.env.SYSTEM_USER_PRIVATE_KEY_FILE ?? process.env.ZITADEL_LOGINCLIENT_KEYFILE;
  if (secretFile) {
    return readFileSync(secretFile, "utf8");
  }
  throw new Error("No server credential available to authenticate user verification state");
}

export function createUserVerification(userId: string, fingerprintId: string, now = Date.now()): string {
  const payload = `${userId}:${fingerprintId}:${now}`;
  const signature = crypto.createHmac("sha256", userVerificationSecret()).update(payload).digest("hex");
  return `${now}.${signature}`;
}

export function userVerificationIsFresh(issuedAt: number, now = Date.now()): boolean {
  return Number.isSafeInteger(issuedAt) && issuedAt <= now && now - issuedAt <= USER_VERIFICATION_MAX_AGE_MS;
}
