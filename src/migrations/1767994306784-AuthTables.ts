import { MigrationInterface, QueryRunner } from "typeorm";

export class AuthTables1767994306784 implements MigrationInterface {
    name = 'AuthTables1767994306784'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "refresh_tokens" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "clientId" character varying, "tokenHash" character varying NOT NULL, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "revoked" boolean NOT NULL DEFAULT false, "rotatedFrom" character varying, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "userId" uuid, CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "token_blacklist" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "jti" character varying NOT NULL, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "reason" character varying NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_3e37528d03f0bd5335874afa48d" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "auth_audit" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "subjectId" character varying NOT NULL, "subjectType" character varying NOT NULL, "event" character varying NOT NULL, "ip" character varying NOT NULL, "userAgent" character varying NOT NULL, "success" boolean NOT NULL DEFAULT true, "metadataJson" jsonb, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_4f9a93d6564ca73e717de59d4cc" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "clients" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "clientId" character varying NOT NULL, "partnerId" character varying NOT NULL, "role" character varying NOT NULL, "division" character varying, "clientSecretHash" character varying NOT NULL, "scopes" text array NOT NULL DEFAULT '{}', "enabled" boolean NOT NULL DEFAULT true, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "UQ_c8526f623c0beed53b60cb31bf5" UNIQUE ("clientId"), CONSTRAINT "PK_f1ab7cf3a5714dbc6bb4e1c28a4" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_610102b60fea1455310ccd299de" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_610102b60fea1455310ccd299de"`);
        await queryRunner.query(`DROP TABLE "clients"`);
        await queryRunner.query(`DROP TABLE "auth_audit"`);
        await queryRunner.query(`DROP TABLE "token_blacklist"`);
        await queryRunner.query(`DROP TABLE "refresh_tokens"`);
    }

}
