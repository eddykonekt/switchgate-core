import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  OneToOne,
} from 'typeorm';
import { PasswordResetToken } from '../../auth/entities/password-reset-token.entity';
import { AdminMfaSecret } from '../../auth/entities/admin-mfa-secret.entity';
import { OtpCode } from '../../auth/entities/otp-code.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: 'user' })
  role: string;

  @Column({ nullable: true })
  msisdn?: string;

  @Column({ nullable: true })
  pin?: string;

  @Column({ nullable: true })
  clientId?: string;

  @Column({ default: false })
  isVerified: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relations
  @OneToMany(() => RefreshToken, refreshToken => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => PasswordResetToken, reset => reset.user)
  passwordResetTokens: PasswordResetToken[];

  @OneToOne(() => AdminMfaSecret, mfa => mfa.admin)
  mfaSecret: AdminMfaSecret;

  @OneToMany(() => OtpCode, otp => otp.email)
  otpCodes: OtpCode[];
  requireOtp: any;
  secretHash: string;
  client_id: any;
  scopes: any;
    emailVerificationTokens: any;
}