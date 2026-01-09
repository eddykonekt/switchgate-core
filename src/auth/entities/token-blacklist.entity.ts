import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('token_blacklist')
export class TokenBlacklist {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  jti: string; // JWT ID

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column()
  reason: string;

  @CreateDateColumn()
  createdAt: Date;
}