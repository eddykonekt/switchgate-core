import dotenv from 'dotenv';
dotenv.config();

export const env = {
  nodeEnv: process.env.NODE_ENV || 'production',
  jwtSecret: process.env.JWT_SECRET!,
  jwtIssuer: process.env.JWT_ISSUER || 'switchgate',
  jwtAccessTtl: process.env.JWT_ACCESS_TTL || '15m',
  jwtRefreshTtl: process.env.JWT_REFRESH_TTL || '30d',
  dbUrl: process.env.DATABASE_URL!,
  otpTtlSeconds: Number(process.env.OTP_TTL_SECONDS || 180),
  otpMaxAttempts: Number(process.env.OTP_MAX_ATTEMPTS || 5),
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60000),
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 100),
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS || 12),
  partnerTokenTtl: process.env.PARTNER_TOKEN_TTL || '10m',
  allowedClockSkewSec: Number(process.env.JWT_CLOCK_SKEW || 30),
};