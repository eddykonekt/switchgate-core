import { Injectable, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';

@Injectable()
export class AppService {
  getHello(): string {
    return 'SwitchGate -Where Value Becomes Fluid!';
  }
}

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    TypeOrmModule.forRootAsync({
      useFactory: () => {
        console.log("🔐 Loaded ENV:");
        console.log("DB_HOST:", process.env.DB_HOST);
        console.log("DB_USER:", process.env.DB_USER);
        console.log("DB_PASSWORD:", process.env.DB_PASSWORD);

        return {
          type: 'postgres',
          host: process.env.DB_HOST || 'localhost',
          port: parseInt(process.env.DB_PORT || '5432', 10),
          username: process.env.DB_USER || 'switchgate_user',
          password: process.env.DB_PASSWORD || 'test1234',
          database: process.env.DB_NAME || 'switchgate_test',
          ssl: process.env.DB_SSL === 'true',
          entities: [User],
          
        };
      },
    }),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {
}