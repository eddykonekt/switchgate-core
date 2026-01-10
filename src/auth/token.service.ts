import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { RefreshToken } from '../users/entities/refresh-token.entity';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';

@Injectable()
export class TokenService {
  refreshTokenRepo: any;
  constructor(
    private readonly jwt: JwtService, refreshTokenRepo: RefreshTokenRepository,
  ) {}

  issueAccess(payload: any, ttl = process.env.JWT_ACCESS_TTL || '15m') {
    return this.jwt.sign(payload, { expiresIn: ttl='15m', issuer: 'switchgate' });
  }

  async issueRefresh(userId: string, clientId?: string) {
    const raw = crypto.randomBytes(64).toString('hex');
    const hash = await bcrypt.hash(raw, 12);
    const expiresAt = new Date(Date.now() + Number(process.env.REFRESH_TTL_SECONDS || 2592000) * 1000);
    await this.refreshTokenRepo.saveToken({ userId, clientId, tokenHash: hash, expiresAt, });
    return raw;
  }

  async rotateRefresh(oldToken: string, userId: string, clientId?: string) {
    const rec = await findLatestRefreshToken(userId);
    if (!rec || rec.revoked || new Date(rec.expiresAt) < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const ok = await bcrypt.compare(oldToken, rec.tokenHash);
    if (!ok) throw new UnauthorizedException('Invalid refresh token');

    await revokeRefreshToken(rec.id, 'rotated');
    return this.issueRefresh(userId, clientId);
  }

  async revokeByToken(raw: string, userId: string) {
    const rec = await findLatestRefreshToken(userId);
    if (!rec) return;
    const ok = await bcrypt.compare(raw, rec.tokenHash);
    if (ok) await revokeRefreshToken(rec.id, 'logout');
  }
}

// Wire these to your repository/ORM
async function saveRefreshToken(_: any) {}
async function findLatestRefreshToken(_: string) { return null as any; }
async function revokeRefreshToken(_: string, __: string) {}
