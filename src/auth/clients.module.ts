import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ClientRegistryService } from './client-registry.service';
import { ClientsController } from './clients.controller';
import { Client } from './entities/client.entity';
import { AppMailer } from 'src/mailer/mailer.service';

@Module({
  imports: [TypeOrmModule.forFeature([Client])],
  controllers: [ClientsController],
  providers: [ClientRegistryService, AppMailer],
  exports: [ClientRegistryService],
})
export class ClientsModule {}