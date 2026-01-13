import { MigrationInterface, QueryRunner } from "typeorm";

export class AddRevokedTokens1670000000000 implements MigrationInterface {
  name = 'AddRevokedTokens1670000000000'

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "revoked_tokens" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "token" character varying NOT NULL,
        "revokedAt" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "UQ_revoked_tokens_token" UNIQUE ("token"),
        CONSTRAINT "PK_revoked_tokens_id" PRIMARY KEY ("id")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "revoked_tokens"`);
  }
}