import { signAccessToken } from '../utils/jwt';
import { schemas } from '../../common/validator';
import { errors } from '../../common/errors';
import { logger } from '../../common/logger';
import { db } from '../../modules/db';
import { adapters } from '../../modules/adapters'; // telco adapters registry

export async function userLogin(input: unknown) {
  const { msisdn, pin, otp, deviceFingerprint } = schemas.userLogin.parse(input);

  const user = await db.users.findByMsisdn(msisdn);
  if (!user) throw errors.Unauthorized('User not found');

  const telco = user.telco;
  const adapter = adapters.get(telco);
  if (!adapter) throw errors.BadRequest('Unsupported telco');

  const pinOk = await adapter.validatePin(msisdn, pin);
  if (!pinOk) throw errors.Unauthorized('Invalid PIN');

  const otpOk = await adapter.verifyOtp(msisdn, otp);
  if (!otpOk) throw errors.Unauthorized('Invalid OTP');

  await db.devices.bind(msisdn, deviceFingerprint);

  const token = signAccessToken({ sub: user.id, role: 'USER', msisdn });
  logger.info(`User login: ${msisdn}`);
  return { access_token: token, token_type: 'Bearer', expires_in: 900 };
}