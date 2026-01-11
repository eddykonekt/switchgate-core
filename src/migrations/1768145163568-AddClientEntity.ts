import { MigrationInterface, QueryRunner } from "typeorm";

export class AddClientEntity1768145163568 implements MigrationInterface {
    name = 'AddClientEntity1768145163568'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" ADD "isVerified" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "clients" ADD "apiKey" character varying NOT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "clients" DROP COLUMN "apiKey"`);
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "isVerified"`);
    }

}
