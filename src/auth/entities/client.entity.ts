import { ApiProperty } from '@nestjs/swagger';
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, BeforeInsert } from 'typeorm';
import { randomBytes } from 'crypto';

@Entity('clients')
export class Client {
  @ApiProperty()
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty()
  @Column({ unique: true })
  clientId: string;

  @ApiProperty()
  @Column()
  partnerId: string;

  @ApiProperty()
  @Column()
  role: string;

  @ApiProperty({ required: false })
  @Column({ nullable: true })
  division?: string;

  @ApiProperty()
  @Column()
  clientSecretHash: string;

  @ApiProperty({ type: [String] })
  @Column("text", { array: true, default: () => "'{}'" })
  scopes: string[];

  @ApiProperty()
  @Column({ default: true })
  enabled: boolean;

  @ApiProperty()
  @Column()
  apiKey: string;

  @ApiProperty()
  @Column({ default: false })
  archived: boolean;

  @ApiProperty()
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty()
  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  generateApiKey() {
    const prefix = 'client_';
    this.apiKey = prefix + randomBytes(24).toString('hex');
  }
}