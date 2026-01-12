import { MigrationInterface, QueryRunner } from "typeorm";

export class Baseline1768218944292 implements MigrationInterface {
    name = 'Baseline1768218944292'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "email_verification_tokens" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "token" character varying NOT NULL, "expiresAt" TIMESTAMP NOT NULL, "used" boolean NOT NULL DEFAULT false, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "userId" uuid, CONSTRAINT "PK_417a095bbed21c2369a6a01ab9a" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "users" ADD "isVerified" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "users" ADD "enabled" boolean NOT NULL DEFAULT true`);
        await queryRunner.query(`ALTER TABLE "users" ADD "archived" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "clients" ADD "apiKey" character varying NOT NULL`);
        await queryRunner.query(`ALTER TABLE "clients" ADD "archived" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "email_verification_tokens" ADD CONSTRAINT "FK_10f285d038feb767bf7c2da14b3" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "email_verification_tokens" DROP CONSTRAINT "FK_10f285d038feb767bf7c2da14b3"`);
        await queryRunner.query(`ALTER TABLE "clients" DROP COLUMN "archived"`);
        await queryRunner.query(`ALTER TABLE "clients" DROP COLUMN "apiKey"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "archived"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "enabled"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "isVerified"`);
        await queryRunner.query(`DROP TABLE "email_verification_tokens"`);
    }

}
