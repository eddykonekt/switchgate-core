import { z } from 'zod';

export const schemas = {
  adminLogin: z.object({
    email: z.string().email(),
    password: z.string().min(8),
    otp: z.string().optional(),
  }),
  userLogin: z.object({
    msisdn: z.string().min(10).max(15),
    pin: z.string().min(4).max(6),
    otp: z.string().length(6),
    deviceFingerprint: z.string().min(16),
  }),
  partnerToken: z.object({
    client_id: z.string().min(3).max(64),
    client_secret: z.string().min(16).max(128),
    grant_type: z.literal('client_credentials'),
    scope: z.string().optional(),
  }),
};