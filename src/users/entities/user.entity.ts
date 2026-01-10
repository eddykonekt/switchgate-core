import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { RefreshToken } from './refresh-token.entity';
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

  @Column({ default: true })
  isActive: boolean;

  @OneToMany(() => RefreshToken, token => token.user)
refreshTokens: RefreshToken[];
}