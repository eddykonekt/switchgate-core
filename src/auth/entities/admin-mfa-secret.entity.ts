// admin-mfa-secret.entity.ts
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, OneToOne, JoinColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';

@Entity('admin_mfa_secrets')
export class AdminMfaSecret {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'uuid' })
  adminId: string;

  @Column('text')
  secret: string;

  @CreateDateColumn()
  createdAt: Date;

  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'adminId' })
  admin: User;
}