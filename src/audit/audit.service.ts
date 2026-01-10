import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

@Injectable()
export class AuditService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditRepo: Repository<AuditLog>,
  ) {}

  async record(
    event: string,
    actorId: string | null,
    actorType: 'USER' | 'ADMIN' | 'CLIENT',
    success: boolean,
    req?: any,
  ) {
    const log = this.auditRepo.create({
      event,
      actorId,
      actorType,
      success,
      ip: req?.ip || req?.headers['x-forwarded-for'] || null,
      userAgent: req?.headers['user-agent'] || null,
    });
    return this.auditRepo.save(log);
  }
}
