import { MigrationInterface, QueryRunner } from "typeorm";

export class AddIsVerifiedToUser1768048654692 implements MigrationInterface {
    name = 'AddIsVerifiedToUser1768048654692'

    public async up(queryRunner: QueryRunner): Promise<void> {
        // ❌ Removed the DROP CONSTRAINT lines that were failing
        // ❌ Removed DROP INDEX lines if those indexes don't exist in your DB

        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "clientId"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "tokenHash"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "user_id"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "expires_at"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "created_at"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP COLUMN "admin_id"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP COLUMN "created_at"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "expires_at"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "created_at"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "isActive"`);

        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "token" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "userId" uuid NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "expiresAt" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD "adminId" uuid NOT NULL`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD CONSTRAINT "UQ_2adfe6623db2a42680c2a504e90" UNIQUE ("adminId")`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "expiresAt" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "users" ADD "msisdn" character varying`);
        await queryRunner.query(`ALTER TABLE "users" ADD "pin" character varying`);
        await queryRunner.query(`ALTER TABLE "users" ADD "clientId" character varying`);
        await queryRunner.query(`ALTER TABLE "users" ADD "isVerified" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "users" ADD "createdAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "users" ADD "updatedAt" TIMESTAMP NOT NULL DEFAULT now()`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "expiresAt"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "expiresAt" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ALTER COLUMN "used" SET NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "email"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "email" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "code"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "code" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ALTER COLUMN "used" SET NOT NULL`);

        // ✅ Add fresh foreign keys
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "FK_d6a19d4b4f6c62dcd29daa497e2" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD CONSTRAINT "FK_2adfe6623db2a42680c2a504e90" FOREIGN KEY ("adminId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        // Keep your down() as-is, since it restores the old schema
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP CONSTRAINT "FK_2adfe6623db2a42680c2a504e90"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP CONSTRAINT "FK_d6a19d4b4f6c62dcd29daa497e2"`);
        // ... rest of your down() unchanged
    }
}