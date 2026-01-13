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
    private readonly PasswordresetTokenRepo: Repository<PasswordResetToken>,
    @InjectRepository(EmailVerificationToken)
    private readonly EmailVerificationTokenRepo: Repository<EmailVerificationToken>,
    @InjectRepository(OtpCode)
    private readonly otpCodeRepo: Repository<OtpCode>,
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
    const resetToken = this.PasswordresetTokenRepo.create({ user: { id: userId } as User, token, expiresAt });
    return this.PasswordresetTokenRepo.save(resetToken);
  }

  // Email verification tokens
  async saveEmailVerificationToken(userId: string, token: string, expiresAt: Date) {
    const emailToken = this.EmailVerificationTokenRepo.create({ user: { id: userId } as User, token, expiresAt });
    return this.EmailVerificationTokenRepo.save(emailToken);
  }

  async findEmailVerificationToken(userId: string, token: string) {
    return this.EmailVerificationTokenRepo.findOne({ where: { user: { id: userId }, token } });
  }

  async markEmailVerificationTokenUsed(id: string) {
    await this.EmailVerificationTokenRepo.update(id, { used: true });
  }

  async markEmailVerified(userId: string) {
    await this.userRepo.update(userId, { isVerified: true });
  }

  // OTP handling
  async saveOtpToDb(email: string, code: string, expiresAt: Date): Promise<OtpCode> {
    const otp = this.otpCodeRepo.create({ email, code, expiresAt});
    return this.otpCodeRepo.save(otp);
    }

  async findOtp(email: string, code: string): Promise<OtpCode | null> {
    return this.otpCodeRepo.findOne({ where: { email, code } });
  }

  async markOtpUsed(id: number): Promise<void> {
    await this.otpCodeRepo.update(id, { used: true });
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

async findAllPaginated(page: 1, limit: 10) {
  return this.userRepo.findAndCount({
    skip: (page - 1) * limit,
    take: limit,
    order: { createdAt: 'DESC' },
  });
}

}