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
import { RefreshToken } from './entities/refresh-token.entity';

@Module({
  imports: [
    UsersModule,
    TypeOrmModule.forFeature([RefreshToken]),
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'dev_secret',
      signOptions: { issuer: 'switchgate', expiresIn: '15m' },
    }),
    MailerModule,
  ],
  providers: [AuthService, JwtStrategy, TokenService, MFAService, AuditService, AccountService, ClientRegistryService, RefreshTokenRepository],
  controllers: [AuthController],
  exports: [AuthService, TokenService, RefreshTokenRepository],
})
export class AuthModule {}