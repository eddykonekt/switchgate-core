import * as speakeasy from 'speakeasy';
import { UnauthorizedException } from '@nestjs/common';

export class MFAService {
  setupTotp(appName = 'Switchgate Admin') {
    const secret = speakeasy.generateSecret({ name: appName });
    return { secret: secret.base32, otpauth: secret.otpauth_url };
  }

  verifyTotp(secret: string, token: string) {
    const ok = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });
    if (!ok) throw new UnauthorizedException('Invalid MFA code');
    return true;
  }
}