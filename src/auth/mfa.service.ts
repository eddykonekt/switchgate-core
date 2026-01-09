import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as speakeasy from 'speakeasy';

@Injectable()
export class MFAService {
  setupTotp(secret?: string) {
    const sec = secret || speakeasy.generateSecret({ length: 20 }).base32;
    const otpauth = speakeasy.otpauthURL({ secret: sec, label: 'SwitchGate', issuer: 'SwitchGate' });
    return { secret: sec, otpauth };
  }

  verifyTotp(secret: string, token: string) {
    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
    if (!ok) throw new UnauthorizedException('Invalid TOTP');
    return true;
  }
}
