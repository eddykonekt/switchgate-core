import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { MailerService } from '../mailer/mailer.service';
import { AdminLoginDto, UserLoginDto, ClientCredentialsDto } from './auth.dto';

@Injectable()
export class AuthService {
  saveAdminMfaSecret: any;
  getAdminMfaSecret: any;
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

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
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async adminLogin(body: AdminLoginDto) {
    const admin = await this.usersService.findAdminByEmail(body.email);
    if (!admin) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(body.password, admin.password);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    // Optional OTP validation
    if (admin.requireOtp && body.otp !== '123456') {
      throw new UnauthorizedException('Invalid OTP');
    }

    const payload = { sub: admin.id, role: 'ADMIN', email: admin.email };
    return { access_token: this.jwtService.sign(payload) };
  }

  async userLogin(body: UserLoginDto) {
    const user = await this.usersService.findByMsisdn(body.msisdn);
    if (!user) throw new UnauthorizedException('User not found');

    // Validate PIN + OTP via telco adapter (stubbed here)
    if (body.pin !== user.pin || body.otp !== '123456') {
      throw new UnauthorizedException('Invalid PIN/OTP');
    }

    const payload = { sub: user.id, role: 'USER', msisdn: user.msisdn };
    return { access_token: this.jwtService.sign(payload) };
  }

  async clientCredentials(body: ClientCredentialsDto, role: 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT') {
    const client = await this.usersService.findClientById(body.client_id);
    if (!client || client.role !== role) throw new UnauthorizedException('Invalid client');

    const match = await bcrypt.compare(body.client_secret, client.secretHash);
    if (!match) throw new UnauthorizedException('Invalid secret');

    const payload = { sub: client.id, role, clientId: client.client_id, scopes: client.scopes };
    return { access_token: this.jwtService.sign(payload) };
  }

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
}