import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, Index } from 'typeorm';

@Entity('user_sessions')
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column()
  userId: string;

  @Column({ nullable: true })
  deviceInfo: string; // e.g., "Chrome 121 on Windows 11"

  @Column({ unique: true })
  refreshToken: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ default: true })
  active: boolean;
}