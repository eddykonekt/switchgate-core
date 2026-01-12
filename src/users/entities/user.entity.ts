import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { PasswordResetToken } from '../../auth/entities/password-reset-token.entity';
import { EmailVerificationToken } from '../../auth/entities/email-verification-token.entity';

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

  @Column({ default: true })
  enabled: boolean;

  @Column({ default: false})
  archived: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => RefreshToken, refreshToken => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => PasswordResetToken, token => token.user)
  passwordResetTokens: PasswordResetToken[] ;

  @OneToMany(() => EmailVerificationToken, token => token.user)
  emailVerificationTokens: EmailVerificationToken[];
  
  name: string;
  clientSecretHash: string;
}