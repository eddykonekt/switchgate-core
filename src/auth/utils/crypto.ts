import bcrypt from 'bcrypt';
import { env } from '../../config/env';

export async function hashPassword(password: string) {
  return bcrypt.hash(password, env.bcryptRounds);
}

export async function verifyPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}