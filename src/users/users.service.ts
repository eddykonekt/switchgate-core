import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { OtpCode } from '../auth/entities/otp-code.entity';
import { PasswordResetToken } from '../auth/entities/password-reset-token.entity';
import { EmailVerificationToken } from '../auth/entities/email-verification-token.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(PasswordResetToken)
    private readonly resetTokenRepo: Repository<PasswordResetToken>,
    @InjectRepository(EmailVerificationToken)
    private readonly emailTokenRepo: Repository<EmailVerificationToken>,
    @InjectRepository(OtpCode)
    private readonly otpRepo: Repository<OtpCode>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }

  async findOne(id: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { id } });
  }

  async create(dto: Partial<User>): Promise<User> {
    const user = this.userRepo.create(dto);
    return this.userRepo.save(user);
  }

  async update(id: string, data: Partial<User>): Promise<User> {
    await this.userRepo.update(id, data);
    const updated = await this.findOne(id);
    if (!updated) throw new Error('User with id ${id} not found');
    return updated;
  }

  // Password reset tokens
  async savePasswordResetToken(userId: string, token: string, expiresAt: Date) {
    const resetToken = this.resetTokenRepo.create({ user: { id: userId } as User, token, expiresAt });
    return this.resetTokenRepo.save(resetToken);
  }

  // Email verification tokens
  async saveEmailVerificationToken(userId: string, token: string, expiresAt: Date) {
    const emailToken = this.emailTokenRepo.create({ user: { id: userId } as User, token, expiresAt });
    return this.emailTokenRepo.save(emailToken);
  }

  async findEmailVerificationToken(userId: string, token: string) {
    return this.emailTokenRepo.findOne({ where: { user: { id: userId }, token } });
  }

  async markEmailVerificationTokenUsed(id: string) {
    await this.emailTokenRepo.update(id, { used: true });
  }

  async markEmailVerified(userId: string) {
    await this.userRepo.update(userId, { isVerified: true });
  }

  // OTP handling
  async saveOtpToDb(email: string, code: string, expiresAt: Date): Promise<OtpCode> {
    const otp = this.otpRepo.create({ email, code, expiresAt});
    return this.otpRepo.save(otp);
    }

  async findOtp(email: string, code: string): Promise<OtpCode | null> {
    return this.otpRepo.findOne({ where: { email, code } });
  }

  async markOtpUsed(id: number): Promise<void> {
    await this.otpRepo.update(id, { used: true });
  }

  async findAll({ page, limit }: { page: number; limit: number }) {
  return this.userRepo.find({
    skip: (page - 1) * limit,
    take: limit,
  });
}

async remove(id: string) {
  await this.userRepo.delete(id);
  return { success: true };
}
}