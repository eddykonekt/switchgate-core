import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity('auth_audit')
export class AuthAudit {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  subjectId: string;

  @Column()
  subjectType: 'ADMIN' | 'USER' | 'CLIENT';

  @Column()
  event: string;

  @Column()
  ip: string;

  @Column()
  userAgent: string;

  @Column({ default: true })
  success: boolean;

  @Column({ type: 'jsonb', nullable: true })
  metadataJson: any;

  @CreateDateColumn()
  createdAt: Date;
}