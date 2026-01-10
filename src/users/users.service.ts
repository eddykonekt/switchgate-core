import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';
import { OtpCode } from '../auth/entities/otp-code.entity';
import { PasswordResetToken } from '../auth/entities/password-reset-token.entity';
import { AdminMfaSecret } from '../auth/entities/admin-mfa-secret.entity';
import { EmailVerificationToken } from 'src/auth/entities/email-verification-token.entity';

@Injectable()
export class UsersService {
  saveClientCredentials: any;
  emailVerificationRepo: any;
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,

    @InjectRepository(OtpCode)
    private otpRepo: Repository<OtpCode>,

    @InjectRepository(PasswordResetToken)
    private passwordResetRepo: Repository<PasswordResetToken>,

    @InjectRepository(AdminMfaSecret)
    private mfaRepo: Repository<AdminMfaSecret>,
  ) {}

  // ---------------- User CRUD ----------------
  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = new User();
    user.email = createUserDto.email;
    user.password = await bcrypt.hash(createUserDto.password, 10);
    user.role = createUserDto.role || 'user';
    return this.usersRepository.save(user);
  }

  async findOne(id: string): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`User with ID ${id} not found`);
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.findOne(id);
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }
    Object.assign(user, updateUserDto);
    return this.usersRepository.save(user);
  }

  async remove(id: string): Promise<void> {
    const result = await this.usersRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findAll({ page, limit }: { page: number; limit: number }) {
    const [data, total] = await this.usersRepository.findAndCount({
      skip: (page - 1) * limit,
      take: limit,
    });

    return {
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  // ---------------- OTP ----------------
  async saveOtpToDb(email: string, code: string, expiresAt: Date) {
    const otp = this.otpRepo.create({ email, code, expiresAt });
    return this.otpRepo.save(otp);
  }

  async findOtp(email: string, code: string): Promise<OtpCode | null> {
    return this.otpRepo.findOne({ where: { email, code } });
  }

  async markOtpUsed(id: number) {
    await this.otpRepo.update(id, { used: true });
  }

  // ---------------- Password Reset ----------------
  async savePasswordResetToken(userId: string, token: string, expiresAt: Date) {
    const reset = this.passwordResetRepo.create({ userId, token, expiresAt });
    return this.passwordResetRepo.save(reset);
  }

  // ---------------- MFA ----------------
  async saveMfaSecret(adminId: string, secret: string) {
    const mfa = this.mfaRepo.create({ adminId, secret });
    return this.mfaRepo.save(mfa);
  }

  async getMfaSecret(adminId: string): Promise<string | null> {
    const record = await this.mfaRepo.findOne({ where: { adminId } });
    return record ? record.secret : null;
  }

  // ---------------- Relations ----------------
  async findOneWithRelations(id: string): Promise<User> {
    const user = await this.usersRepository.findOne({
      where: { id },
      relations: ['passwordResetTokens', 'mfaSecret', 'otpCodes'],
    });
    if (!user) throw new NotFoundException(`User with ID ${id} not found`);
    return user;
  }

  // ---------------- TODO: Implement these if needed ----------------
  async findAdminByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email, role: 'admin' } });
  }

  async findByMsisdn(msisdn: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { msisdn } });
  }

  async findClientById(clientId: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { clientId } });
  }

  // ---------------- Email Verification ----------------
async saveEmailVerificationToken(userId: string, token: string, expiresAt: Date) {
  const record = this.emailVerificationRepo.create({ user: { id: userId }, token, expiresAt });
  return this.emailVerificationRepo.save(record);
}

async findEmailVerificationToken(userId: string, token: string): Promise<EmailVerificationToken | null> {
  return this.emailVerificationRepo.findOne({ where: { user: { id: userId }, token } });
}

async markEmailVerificationTokenUsed(id: string) {
  await this.emailVerificationRepo.update(id, { used: true });
}

async markEmailVerified(userId: string) {
  await this.usersRepository.update(userId, { isVerified: true });
}
}