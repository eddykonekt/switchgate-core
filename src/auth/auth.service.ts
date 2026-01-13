import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { AppMailer } from '../mailer/mailer.service';
import { RegisterDto } from './dto/register.dto';
import { v4 as uuid } from 'uuid';
import { ClientCredentialsDto } from './auth.dto';
import { AuditService } from './audit.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Client } from '../auth/entities/client.entity';
import { RevokedToken } from './entities/revoked-token.entity';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly Appmailer: AppMailer,
    private readonly auditService: AuditService,
    @InjectRepository(Client)
    private readonly clientRepo: Repository<Client>,
    @InjectRepository(RevokedToken)
    private readonly revokedTokenRepo: Repository<RevokedToken>,
  ) {}

  // ---------------- User Validation ----------------
  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (!user) return null;

    const match = await bcrypt.compare(pass, user.password);
    if (!match) return null;

    const { password, ...safeUser } = user;
    return safeUser;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- User Login ----------------
  async userLogin(email: string, password: string, req?: any) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');
    if (!user.isVerified) throw new UnauthorizedException('Please verify your email before logging in');

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      await this.auditService.record('LOGIN', user.id, 'USER', false, req);
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.auditService.record('LOGIN', user.id, 'USER', true, req);

    const payload = { sub: user.id, email: user.email, role: user.role };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- Admin Login ----------------
  async adminLogin(email: string, password: string) {
    const admin = await this.usersService.findByEmail(email);
    if (!admin || admin.role !== 'Admin') throw new UnauthorizedException('Invalid credentials');
    if (!admin.isVerified) throw new UnauthorizedException('Please verify your email before logging in');

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) throw new UnauthorizedException('Invalid credentials');

    const payload = { sub: admin.id, email: admin.email, role: admin.role };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- Client Credentials ----------------
  async clientCredentials(body: ClientCredentialsDto, role: 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT') {
    const client = await this.clientRepo.findOne({ where: { clientId: body.client_id } });
    if (!client || client.role !== role) throw new UnauthorizedException('Invalid client');

    const match = await bcrypt.compare(body.client_secret, client.clientSecretHash);
    if (!match) throw new UnauthorizedException('Invalid secret');

    const payload = { sub: client.id, role, clientId: client.clientId, scopes: client.scopes };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- Password Reset ----------------
  async requestPasswordReset(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new BadRequestException('User not found');

    const token = this.jwtService.sign(
      { sub: user.id },
      { secret: process.env.PASSWORD_RESET_SECRET || 'reset_secret', expiresIn: '15m' },
    );

    const resetLink = `https://switchgate.com/reset?token=${token}`;

    await this.Appmailer.sendWelcomeEmail(user.email, resetLink); // ✅ no user.name

    await this.usersService.savePasswordResetToken(user.id, token, new Date(Date.now() + 15 * 60 * 1000));

    return { message: 'Password reset link sent', token };
  }

  async resetPassword(token: string, newPassword: string) {
    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.PASSWORD_RESET_SECRET || 'reset_secret',
      });
      const user = await this.usersService.findOne(payload.sub);
      if (!user) throw new BadRequestException('Invalid token');

      const hashed = await bcrypt.hash(newPassword, 10);
      await this.usersService.update(user.id, { password: hashed });

      return { message: 'Password successfully updated' };
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  // ---------------- OTP ----------------
  async sendOtp(email: string) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await this.usersService.saveOtpToDb(email, otp, expiresAt);
    await this.Appmailer.sendOtpEmail(email, otp);

    return { message: 'OTP sent to email' };
  }

  async verifyOtp(email: string, otp: string) {
    const record = await this.usersService.findOtp(email, otp);
    if (!record) return { success: false, message: 'No OTP found or expired' };
    if (record.expiresAt < new Date()) return { success: false, message: 'OTP has expired' };
    if (record.used) return { success: false, message: 'OTP already used' };

    await this.usersService.markOtpUsed(record.id);
    return { success: true, message: 'OTP verified successfully' };
  }

  // ---------------- Registration ----------------
  async register(dto: RegisterDto) {
    const user = await this.usersService.create(dto);

    if (['PARTNER', 'ENTERPRISE', 'GOVERNMENT'].includes(dto.role)) {
      const clientId = uuid();
      const clientSecret = uuid();
      const secretHash = await bcrypt.hash(clientSecret, 10);

      const client = this.clientRepo.create({
        clientId,
        partnerId: user.id,
        role: dto.role,
        clientSecretHash: secretHash,
        scopes: [],
        enabled: true,
      });
      await this.clientRepo.save(client);

      await this.Appmailer.sendClientWelcomeEmail(
        user.email,
        clientId,
        clientSecret,
        client.apiKey,
        dto.role,
      );

      return { message: 'Client registered successfully. Credentials sent to email.' };
    }

    if (dto.role === 'USER') {
      const verifyToken = this.jwtService.sign(
        { sub: user.id },
        { secret: process.env.EMAIL_VERIFY_SECRET || 'verify_secret', expiresIn: '24h' },
      );

      await this.usersService.saveEmailVerificationToken(user.id, verifyToken, new Date(Date.now() + 24 * 60 * 60 * 1000));

      const verificationLink = `https://switchgate.com/verify-email?token=${verifyToken}`;
      await this.Appmailer.sendWelcomeEmail(user.email, verificationLink);

      return { message: 'User registered successfully. Verification email sent.' };
    }
  }

  async verifyEmail(token: string, req?: any) {
    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.EMAIL_VERIFY_SECRET || 'verify_secret',
      });

      const record = await this.usersService.findEmailVerificationToken(payload.sub, token);
      if (!record || record.expiresAt < new Date() || record.used) {
        await this.auditService.record('EMAIL_VERIFIED', payload.sub, 'USER', false, req);
        throw new BadRequestException('Invalid or expired token');
      }

      await this.usersService.markEmailVerified(payload.sub);
      await this.usersService.markEmailVerificationTokenUsed(record.id);

      await this.auditService.record('EMAIL_VERIFIED', payload.sub, 'USER', true, req);
      return { message: 'Email verified successfully' };
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async revokeToken(refreshToken: string): Promise<{ message: string }> {
    const revoked = this.revokedTokenRepo.create({ token: refreshToken });
    await this.revokedTokenRepo.save(revoked);
    return { message: 'Token revoked successfully' };
  }

  async saveAdminMfaSecret(userId: string, secret: string) {
    // TODO: Persist MFA secret in DB
    return {success: true};
  }

  async getAdminMfaSecret(userId: string) {
    // TODO; fetch MFA secret from DB
    return {secret: 'dummy-secret'};
  }
}
