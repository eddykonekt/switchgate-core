import { signAccessToken } from '../utils/jwt';
import { verifyPassword } from '../utils/crypto';
import { schemas } from '../../common/validator';
import { errors } from '../../common/errors';
import { logger } from '../../common/logger';
import { db } from '../../modules/db';

export async function adminLogin(input: unknown) {
  const { email, password, otp } = schemas.adminLogin.parse(input);

  const admin = await db.admins.findByEmail(email);
  if (!admin) throw errors.Unauthorized('Invalid credentials');

  const ok = await verifyPassword(password, admin.passwordHash);
  if (!ok) throw errors.Unauthorized('Invalid credentials');

  if (admin.requireOtp) {
    if (!otp) throw errors.BadRequest('OTP required');
    const otpKey = `admin:${email}`;
    // verify via your mailer/otp store
    const valid = await db.otps.verify(otpKey, otp);
    if (!valid) throw errors.Unauthorized('Invalid OTP');
  }

  const token = signAccessToken({ sub: admin.id, role: 'ADMIN' });
  logger.info(`Admin login: ${email}`);
  return { access_token: token, token_type: 'Bearer', expires_in: 900 };
}