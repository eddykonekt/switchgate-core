import { MigrationInterface, QueryRunner } from "typeorm";

export class AddRelationsToUserEntity1768046282884 implements MigrationInterface {
    name = 'AddRelationsToUserEntity1768046282884'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP CONSTRAINT "password_reset_tokens_user_id_fkey"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP CONSTRAINT "admin_mfa_secrets_admin_id_fkey"`);
        await queryRunner.query(`DROP INDEX "public"."idx_reset_user_token"`);
        await queryRunner.query(`DROP INDEX "public"."idx_admin_mfa_unique"`);
        await queryRunner.query(`DROP INDEX "public"."idx_otp_email_code"`);
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
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "FK_d6a19d4b4f6c62dcd29daa497e2" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD CONSTRAINT "FK_2adfe6623db2a42680c2a504e90" FOREIGN KEY ("adminId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP CONSTRAINT "FK_2adfe6623db2a42680c2a504e90"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP CONSTRAINT "FK_d6a19d4b4f6c62dcd29daa497e2"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ALTER COLUMN "used" DROP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "code"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "code" character varying(10) NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "email"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "email" character varying(255) NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ALTER COLUMN "used" DROP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "expiresAt"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "updatedAt"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "clientId"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "pin"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "msisdn"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "otp_codes" DROP COLUMN "expiresAt"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP CONSTRAINT "UQ_2adfe6623db2a42680c2a504e90"`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" DROP COLUMN "adminId"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "createdAt"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "expiresAt"`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN "token"`);
        await queryRunner.query(`ALTER TABLE "users" ADD "isActive" boolean NOT NULL DEFAULT true`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
        await queryRunner.query(`ALTER TABLE "otp_codes" ADD "expires_at" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD "admin_id" uuid NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "expires_at" TIMESTAMP NOT NULL`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD "user_id" uuid NOT NULL`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "tokenHash" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD "clientId" character varying`);
        await queryRunner.query(`CREATE INDEX "idx_otp_email_code" ON "otp_codes" ("code", "email") `);
        await queryRunner.query(`CREATE UNIQUE INDEX "idx_admin_mfa_unique" ON "admin_mfa_secrets" ("admin_id") `);
        await queryRunner.query(`CREATE INDEX "idx_reset_user_token" ON "password_reset_tokens" ("token", "user_id") `);
        await queryRunner.query(`ALTER TABLE "admin_mfa_secrets" ADD CONSTRAINT "admin_mfa_secrets_admin_id_fkey" FOREIGN KEY ("admin_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

}
