import { DataSource } from 'typeorm';
import { User } from './users/entities/user.entity';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USER || 'switchgate_user',
  password: process.env.DB_PASSWORD || 'test1234',
  database: process.env.DB_NAME || 'switchgate_test',
  entities: [User],
  migrations: ['dist/migrations/*.js'], // compiled migrations
  synchronize: false, // turn off in prod
});