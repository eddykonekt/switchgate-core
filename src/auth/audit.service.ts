import { Injectable } from '@nestjs/common';

@Injectable()
export class AuditService {
  auditRepo: any;
  async record(event: string, subjectId: string, subjectType: 'ADMIN' | 'USER' | 'CLIENT', success: boolean, req: any, metadata?: any) {
  await this.auditRepo.save({
    subjectId,
    subjectType,
    event,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    success,
    metadataJson: metadata,
  });
}
}
