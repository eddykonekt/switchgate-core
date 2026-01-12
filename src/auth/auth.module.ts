import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './jwt.strategy';
import { TokenService } from './token.service';
import { MFAService } from './mfa.service';
import { AuditService } from './audit.service';
import { AccountService } from './account.service';
import { ClientRegistryService } from './client-registry.service';
import { MailerModule } from '../mailer/mailer.module';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RedisModule } from '../redis/redis.module';
import { OtpCode } from './entities/otp-code.entity';
import { Client } from './entities/client.entity';
import { AdminUsersService } from './admin-users.service';
import { AdminUsersController } from './admin-users.controller';
import { AdminClientsController } from './admin-clients.controller';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { AdminMfaSecret } from './entities/admin-mfa-secret.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from 'src/users/entities/user.entity';

@Module({
  imports: [
    UsersModule,
    TypeOrmModule.forFeature([User, OtpCode, PasswordResetToken, AdminMfaSecret, RefreshToken, Client]),
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'dev_secret',
      signOptions: { issuer: 'switchgate', expiresIn: '15m' },
    }),
    MailerModule,
    RedisModule,
  ],
  providers: [AuthService, JwtStrategy, TokenService, MFAService, AuditService, AccountService, ClientRegistryService, RefreshTokenRepository, AdminUsersService],
  controllers: [AuthController, AdminClientsController, AdminUsersController],
  exports: [AuthService, TokenService, RefreshTokenRepository, ClientRegistryService],
})
export class AuthModule {}