// src/auth/token.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RevokedToken } from './entities/revoked-token.entity';
import { ConfigService } from '@nestjs/config';
import { AuditService } from './audit.service';

type AccessPayload = {
  sub: string;
  email?: string;
  role?: string;
  scopes?: string[];
};

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectRepository(RevokedToken)
    private readonly revokedTokenRepo: Repository<RevokedToken>,
    private readonly auditService: AuditService,
  ) {}

  // ---------- Issue tokens ----------
  issueAccess(payload: AccessPayload): string {
    const expiresIn = this.configService.get<string>('JWT_EXPIRES_IN') ?? '15m';
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET') ?? 'dev_secret',
      expiresIn: expiresIn as any,
    });
  }

  issueRefresh(sub: string): string {
    const expiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '30d';
    return this.jwtService.sign({ sub }, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET') ?? 'refresh_secret',
      expiresIn: expiresIn as any,
    });
  }

  // ---------- Validation helpers ----------
  async isRevoked(token: string): Promise<boolean> {
    const found = await this.revokedTokenRepo.findOne({ where: { token } });
    return !!found;
  }

  verifyRefreshOrThrow(token: string): any {
    try {
      return this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  // ---------- Rotation & revocation ----------
  async rotateRefresh(oldRefresh: string, userId: string): Promise<string> {
    if (await this.isRevoked(oldRefresh)) {
      await this.auditService.record('TOKEN_REFRESH', userId, 'USER', false, null);
      throw new UnauthorizedException('Refresh token has been revoked');
    }

    const payload = this.verifyRefreshOrThrow(oldRefresh);
    if (payload.sub !== userId) {
      await this.auditService.record('TOKEN_REFRESH', userId, 'USER', false, null);
      throw new UnauthorizedException('Refresh token subject mismatch');
    }

    await this.revokeByToken(oldRefresh, userId);
    const newRefresh = this.issueRefresh(userId);
    await this.auditService.record('TOKEN_REFRESH', userId, 'USER', true, null);
    return newRefresh;
  }

  async revokeByToken(refreshToken: string, userId?: string): Promise<void> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
      if (userId && payload.sub !== userId) {
        await this.revokedTokenRepo.save(this.revokedTokenRepo.create({ token: refreshToken }));
        await this.auditService.record('TOKEN_REVOKED', userId ?? 'UNKOWN', 'USER', false, null);
        throw new UnauthorizedException('Token does not belong to user');
      }
    } catch {
      // If verification fails, still store token to prevent reuse
    }

    const revoked = this.revokedTokenRepo.create({ token: refreshToken });
    await this.revokedTokenRepo.save(revoked);
  }
}