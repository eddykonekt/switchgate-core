import { Pool } from 'pg';
import { env } from '../../config/env';

const pool = new Pool({ connectionString: env.dbUrl });

export const db = {
  admins: {
    async findByEmail(email: string) {
      const { rows } = await pool.query('SELECT * FROM admins WHERE email=$1', [email]);
      return rows[0] || null;
    },
  },
  users: {
    async findByMsisdn(msisdn: string) {
      const { rows } = await pool.query('SELECT * FROM users WHERE msisdn=$1', [msisdn]);
      return rows[0] || null;
    },
  },
  devices: {
    async bind(msisdn: string, fingerprint: string) {
      await pool.query(
        'INSERT INTO devices (msisdn, fingerprint) VALUES ($1,$2) ON CONFLICT (msisdn,fingerprint) DO NOTHING',
        [msisdn, fingerprint]
      );
    },
  },
  clients: {
    async findById(clientId: string) {
      const { rows } = await pool.query('SELECT * FROM clients WHERE client_id=$1', [clientId]);
      return rows[0] || null;
    },
    async verifySecret(clientId: string, secret: string) {
      const rec = await this.findById(clientId);
      if (!rec) return false;
      // use bcrypt to compare secret with hash
      const bcrypt = await import('bcrypt');
      return bcrypt.compare(secret, rec.client_secret_hash);
    },
  },
  otps: {
    async verify(key: string, code: string) {
      const { rows } = await pool.query('SELECT * FROM otp_store WHERE key=$1', [key]);
      const rec = rows[0];
      if (!rec) return false;
      if (new Date(rec.expires_at).getTime() < Date.now()) return false;
      const attempts = rec.attempts + 1;
      await pool.query('UPDATE otp_store SET attempts=$1 WHERE key=$2', [attempts, key]);
      return rec.code === code;
    },
  },
};