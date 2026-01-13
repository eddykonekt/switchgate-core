import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserSession } from './entities/user-session.entity';
import { TokenService } from './token.service';
import { AuditService } from './audit.service';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(UserSession)
    private readonly sessionRepo: Repository<UserSession>,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
  ) {}

  async createSession(userId: string, deviceInfo?: string): Promise<{ refreshToken: string; sessionId: string }> {
    const refreshToken = this.tokenService.issueRefresh(userId);
    const session = this.sessionRepo.create({ userId, deviceInfo, refreshToken, active: true });
    await this.sessionRepo.save(session);
    await this.auditService.record('SESSION_CREATE', userId, 'USER', true, null);
    return { refreshToken, sessionId: session.id };
  }

  async revokeSessionByToken(refreshToken: string, userId: string): Promise<void> {
    const session = await this.sessionRepo.findOne({ where: { refreshToken, userId } });
    if (!session) throw new UnauthorizedException('Session not found');

    session.active = false;
    await this.sessionRepo.save(session);
    await this.tokenService.revokeByToken(refreshToken, userId);
    await this.auditService.record('SESSION_REVOKE', userId, 'USER', true, null);
  }

  async revokeAllSessions(userId: string): Promise<void> {
    const sessions = await this.sessionRepo.find({ where: { userId, active: true } });
    for (const s of sessions) {
      s.active = false;
      await this.sessionRepo.save(s);
      await this.tokenService.revokeByToken(s.refreshToken, userId);
    }
    await this.auditService.record('SESSION_REVOKE_ALL', userId, 'USER', true, null);
  }

  async rotateSession(refreshToken: string, userId: string): Promise<{ refreshToken: string }> {
    const session = await this.sessionRepo.findOne({ where: { refreshToken, userId, active: true } });
    if (!session) throw new UnauthorizedException('Session not found or inactive');

    const newRefresh = await this.tokenService.rotateRefresh(refreshToken, userId);
    session.refreshToken = newRefresh;
    await this.sessionRepo.save(session);
    await this.auditService.record('SESSION_ROTATE', userId, 'USER', true, null);
    return { refreshToken: newRefresh };
  }
}