import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RefreshToken } from '../../users/entities/refresh-token.entity';

@Injectable()
export class RefreshTokenRepository {
  constructor(
    @InjectRepository(RefreshToken)
    private readonly repo: Repository<RefreshToken>,
  ) {}

  async saveToken(token: Partial<RefreshToken>) {
    return this.repo.save(token);
  }

  async findLatestByUser(userId: string) {
    return this.repo.findOne({
      where: { user: { id: userId }, revoked: false },
      order: { createdAt: 'DESC' },
    });
  }

  async revoke(id: string, reason: string) {
    await this.repo.update(id, { revoked: true, rotatedFrom: reason });
  }
}