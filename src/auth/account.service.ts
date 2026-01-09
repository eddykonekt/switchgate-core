import { Injectable, BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AccountService {
  userRepo: any;
  async register(email: string, password: string, msisdn?: string) {
    const exists = await findUserByEmail(email);
    if (exists) throw new BadRequestException('Email already registered');
    const hash = await bcrypt.hash(password, 12);
    const user = await createUser({ email, passwordHash: hash, msisdn, status: 'PENDING' });
    const token = await createActivationToken(user.id);
    // send activation email
    return { message: 'Registered. Check email to activate.' };
  }

  async activate(token: string) {
    const userId = await verifyActivationToken(token);
    await this.userRepo.update(userId, { status: 'ACTIVE' });
    return { message: 'Account activated' };
  }

  async suspend(userId: string, reason: string) {
    await updateUserStatus(userId, 'SUSPENDED');
    // record reason in audit
    return { message: 'Account suspended' };
  }

  async deactivate(userId: string) {
    await updateUserStatus(userId, 'DEACTIVATED');
    return { message: 'Account deactivated' };
  }

  async changePassword(userId: string, current: string, next: string) {
    const user = await findUserById(userId);
    const ok = await bcrypt.compare(current, user.passwordHash);
    if (!ok) throw new BadRequestException('Current password incorrect');
    const hash = await bcrypt.hash(next, 12);
    await updateUserPassword(userId, hash);
    return { message: 'Password changed' };
  }
}

// Placeholder persistence functions—wire to your repository/ORM
async function findUserByEmail(_: string) { return null as any; }
async function createUser(_: any) { return null as any; }
async function createActivationToken(_: string) { return ''; }
async function verifyActivationToken(_: string) { return ''; }
async function updateUserStatus(_: string, __: string) {}
async function findUserById(_: string) { return { passwordHash: '' } as any; }
async function updateUserPassword(_: string, __: string) {}