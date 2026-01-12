import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { randomBytes } from 'crypto';
import { ClientRegisterDto } from '../client/dto/client-register.dto';
import { AppMailer } from '../mailer/mailer.service';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { Client } from '../auth/entities/client.entity'; // adjust to your actual entity

type Role = 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';

@Injectable()
export class ClientRegistryService {
  approveClient: any;
    rotateApiKey: any;
  constructor(
    @InjectRepository(Client)
    private readonly clientRepo: Repository<Client>,
    private readonly mailer: AppMailer,
  ) {}

  async register(dto: ClientRegisterDto) {
    // Save base client record
    const client = await this.clientRepo.save({
      name: dto.name,
      email: dto.email,
      role: dto.clientType,
      enabled: true,
      scopes: [],
    });

    // Generate credentials
    const clientId = this.generateClientId();
    const clientSecret = this.generateClientSecret();
    const apiKey = this.generateApiKey();

    // Hash secret before storing
    const clientSecretHash = await bcrypt.hash(clientSecret, 12);

    await this.clientRepo.update(client.id, {
      clientId,
      clientSecretHash,
      apiKey,
    });

    // Trigger welcome email with credentials
    await this.mailer.sendClientWelcomeEmail(
      client.name,
      client.email,
      clientId,
      clientSecret,
      apiKey,
      dto.clientType,
    );

    return { ...client, clientId, clientSecret, apiKey };
  }

  async issueToken(clientId: string, clientSecret: string, role: Role, requestedScopes?: string[]) {
    const client = await this.clientRepo.findOne({ where: { clientId } });
    if (!client || !client.enabled) throw new UnauthorizedException('Invalid client');
    if (client.role !== role) throw new ForbiddenException('Role mismatch');

    const ok = await bcrypt.compare(clientSecret, client.clientSecretHash);
    if (!ok) throw new UnauthorizedException('Invalid secret');

    const scopes = requestedScopes?.length
      ? requestedScopes.filter(s => client.scopes.includes(s))
      : client.scopes;

    return { client, scopes };
  }

  async rotateSecret(clientId: string) {
    const raw = this.cryptoRandom(48);
    const hash = await bcrypt.hash(raw, 12);
    await this.clientRepo.update({ clientId }, { clientSecretHash: hash });
    return { client_id: clientId, client_secret: raw };
  }

  async setScopes(clientId: string, scopes: string[]) {
    await this.clientRepo.update({ clientId }, { scopes });
  }

  async enable(clientId: string, enabled: boolean) {
    await this.clientRepo.update({ clientId }, { enabled });
  }

  private generateClientId(): string {
    return 'CL-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  }

  private generateClientSecret(): string {
    return 'CS-' + crypto.randomBytes(8).toString('hex');
  }

  private generateApiKey(): string {
    return 'API-' + crypto.randomBytes(12).toString('hex');
  }

  private cryptoRandom(len: number): string {
    return crypto.randomBytes(len).toString('hex');
  }
}