import crypto from 'crypto';
import { env } from '../../config/env';

type OtpRecord = { code: string; expiresAt: number; attempts: number };
const store = new Map<string, OtpRecord>();

export function generateOtp(key: string): string {
  const code = (crypto.randomInt(0, 1000000) + '').padStart(6, '0');
  store.set(key, { code, expiresAt: Date.now() + env.otpTtlSeconds * 1000, attempts: 0 });
  return code;
}

export function verifyOtp(key: string, code: string): boolean {
  const rec = store.get(key);
  if (!rec) return false;
  if (Date.now() > rec.expiresAt) return false;
  rec.attempts += 1;
  if (rec.attempts > env.otpMaxAttempts) return false;
  return rec.code === code;
}

export function invalidateOtp(key: string) {
  store.delete(key);
}