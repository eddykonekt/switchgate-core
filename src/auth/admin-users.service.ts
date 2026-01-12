import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity';

@Injectable()
export class AdminUsersService {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  async enableUser(id: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`User with id ${id} not found`);
    user.enabled = true;
    return this.userRepo.save(user);
  }

  async disableUser(id: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`User with id ${id} not found`);
    user.enabled = false;
    return this.userRepo.save(user);
  }

  async archiveUser(id: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`User with id ${id} not found`);
    user.archived = true;
    return this.userRepo.save(user);
  }

  async createSubAdmin(data: Partial<User>): Promise<User> {
    const user = this.userRepo.create({
      ...data,
      role: 'sub-admin',
      enabled: true,
      archived: false,
    });
    return this.userRepo.save(user);
  }
}