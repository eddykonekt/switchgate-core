import { BadRequestException, Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { MailerService } from '../mailer/mailer.service';
import * as hbs from 'handlebars';
import Redis from 'ioredis';
import { AdminLoginDto, UserLoginDto, ClientCredentialsDto } from './auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
  ) {}

  // ---------------- MFA Secret Management ----------------
  async saveAdminMfaSecret(adminId: string, secret: string) {
    await this.redis.set(`admin:mfa:${adminId}`, secret);
    return { message: 'MFA secret saved successfully' };
  }

  async getAdminMfaSecret(adminId: string) {
    const secret = await this.redis.get(`admin:mfa:${adminId}`);
    if (!secret) {
      throw new BadRequestException('No MFA secret found');
    }
    return { secret };
  }

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

  // ---------------- Admin Login ----------------
  async adminLogin(body: AdminLoginDto) {
    const admin = await this.usersService.findAdminByEmail(body.email);
    if (!admin) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(body.password, admin.password);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    // Optional OTP validation
    if (admin.requireOtp) {
      const storedOtp = await this.redis.get(`otp:${body.email}`);
      if (!storedOtp || storedOtp !== body.otp) {
        throw new UnauthorizedException('Invalid OTP');
      }
      await this.redis.del(`otp:${body.email}`);
    }

    const payload = { sub: admin.id, role: 'ADMIN', email: admin.email };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- User Login ----------------
  async userLogin(body: UserLoginDto) {
    const user = await this.usersService.findByMsisdn(body.msisdn);
    if (!user) throw new UnauthorizedException('User not found');

    const storedOtp = await this.redis.get(`otp:${user.email}`);
    if (body.pin !== user.pin || !storedOtp || storedOtp !== body.otp) {
      throw new UnauthorizedException('Invalid PIN/OTP');
    }
    await this.redis.del(`otp:${user.email}`);

    const payload = { sub: user.id, role: 'USER', msisdn: user.msisdn };
    return { access_token: this.jwtService.sign(payload) };
  }

  // ---------------- Client Credentials ----------------
  async clientCredentials(body: ClientCredentialsDto, role: 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT') {
    const client = await this.usersService.findClientById(body.client_id);
    if (!client || client.role !== role) throw new UnauthorizedException('Invalid client');

    const match = await bcrypt.compare(body.client_secret, client.secretHash);
    if (!match) throw new UnauthorizedException('Invalid secret');

    const payload = { sub: client.id, role, clientId: client.client_id, scopes: client.scopes };
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

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      text: `Click the link to reset your password: ${resetLink}`,
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
    });

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
    const html = hbs.compile(`<p>Your OTP is <b>{{otp}}</b>. It expires in 5 minutes.</p>`)({ otp });

    await this.mailerService.sendMail({
      to: email,
      subject: 'Your Switchgate OTP',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
      html,
    });

    await this.redis.set(`otp:${email}`, otp, 'EX', 300);
    return { message: 'OTP sent to email' };
  }

  async verifyOtp(email: string, otp: string) {
    const stored = await this.redis.get(`otp:${email}`);
    if (!stored) {
      return { success: false, message: 'No OTP found or expired' };
    }

    if (stored !== otp) {
      return { success: false, message: 'Invalid OTP' };
    }

    await this.redis.del(`otp:${email}`);
    return { success: true, message: 'OTP verified successfully' };
  }
}