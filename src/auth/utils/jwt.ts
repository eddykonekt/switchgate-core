import jwt, { SignOptions } from 'jsonwebtoken';
import { env } from '../../config/env';

type AccessPayload = {
  sub: string;
  role: 'ADMIN' | 'USER' | 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';
  scopes?: string[];
  clientId?: string;
  msisdn?: string;
  division?: string;
};

export function signAccessToken(payload: AccessPayload, expiresIn = parseInt(env.jwtAccessTtl)) {
  const options: SignOptions = {
    expiresIn,
    issuer: env.jwtIssuer,
    algorithm: 'HS256',
  };
  return jwt.sign(payload, env.jwtSecret as string, options);
}

export function signPartnerToken(payload: AccessPayload, expiresIn = parseInt(env.partnerTokenTtl)) {
  const options: SignOptions = {
    expiresIn,
    issuer: env.jwtIssuer,
    algorithm: 'HS256',
  };
  return jwt.sign(payload, env.jwtSecret as string, options);
}

export function verifyToken<T = any>(token: string): T {
  return jwt.verify(token, env.jwtSecret, {
    issuer: env.jwtIssuer,
    clockTolerance: env.allowedClockSkewSec,
  }) as T;
}