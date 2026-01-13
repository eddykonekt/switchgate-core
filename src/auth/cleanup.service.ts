import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { RevokedToken } from './entities/revoked-token.entity';

@Injectable()
export class CleanupService {
  private readonly logger = new Logger(CleanupService.name);

  constructor(
    @InjectRepository(RevokedToken)
    private readonly revokedRepo: Repository<RevokedToken>,
  ) {}

  // Run daily at 02:00
  @Cron('0 2 * * *')
  async purgeOldRevokedTokens() {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days
    const result = await this.revokedRepo.delete({ revokedAt: LessThan(cutoff) });
    this.logger.log(`Purged ${result.affected ?? 0} revoked tokens older than 30 days`);
  }
}