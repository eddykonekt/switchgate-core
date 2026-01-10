import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('audit_logs')
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  event: string; // e.g. REGISTER, LOGIN, EMAIL_VERIFIED

  @Column({ nullable: true, type: 'varchar' })
  actorId?: string | null; // userId or clientId

  @Column()
  actorType: string; // USER, ADMIN, CLIENT

  @Column({ default: true })
  success: boolean;

  @Column({ nullable: true })
  ip?: string | null;

  @Column({ nullable: true })
  userAgent?: string | null;

  @CreateDateColumn()
  createdAt: Date;
}