import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('clients')
export class ClientEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  clientId: string;

  @Column()
  partnerId: string;

  @Column({ type: 'varchar' })
  role: string; //'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';

  @Column({ nullable: true })
  division: string;

  @Column()
  clientSecretHash: string;

  @Column('text', { array: true, default: '{}' })
  scopes: string[];

  @Column({ default: true })
  enabled: boolean;

  @Column()
  apiKey: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}