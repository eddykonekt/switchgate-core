import { DataSource } from 'typeorm';
import 'reflect-metadata';
import { User } from './users/entities/user.entity';
import { TokenBlacklist } from './auth/entities/token-blacklist.entity';
import { AuthAudit } from './auth/entities/auth-audit.entity';
import { Client } from './auth/entities/client.entity';
import { RefreshToken } from './auth/entities/refresh-token.entity';
import { OtpCode } from './auth/entities/otp-code.entity';
import { PasswordResetToken } from './auth/entities/password-reset-token.entity';
import { AdminMfaSecret } from './auth/entities/admin-mfa-secret.entity';
import { EmailVerificationToken } from './auth/entities/email-verification-token.entity';
import { RevokedToken } from './auth/entities/revoked-token.entity';
import { UserSession } from './auth/entities/user-session.entity';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USER || 'switchgate_user',
  password: process.env.DB_PASSWORD || 'test1234',
  database: process.env.DB_NAME || 'switchgate_test',
  entities: [User, RefreshToken, TokenBlacklist, Client, AuthAudit, OtpCode, PasswordResetToken, AdminMfaSecret, EmailVerificationToken, RevokedToken, UserSession],
  migrations: [
    process.env.NODE_ENV === 'production'
     ? 'src/migrations/*.ts' 
     : 'dist/migrations/*.js',
  ], // compiled migrations
  synchronize: false, // turn off in prod
});