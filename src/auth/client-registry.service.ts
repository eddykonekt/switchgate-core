import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

type Role = 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';

@Injectable()
export class ClientRegistryService {
  async issueToken(clientId: string, clientSecret: string, role: Role, requestedScopes?: string[]) {
    const client = await findClientById(clientId);
    if (!client || !client.enabled) throw new UnauthorizedException('Invalid client');
    if (client.role !== role) throw new ForbiddenException('Role mismatch');
    const ok = await bcrypt.compare(clientSecret, client.clientSecretHash);
    if (!ok) throw new UnauthorizedException('Invalid secret');

    const scopes = requestedScopes?.length ? requestedScopes.filter(s => client.scopes.includes(s)) : client.scopes;
    return { client, scopes };
  }

  async rotateSecret(clientId: string) {
    const raw = cryptoRandom(48);
    const hash = await bcrypt.hash(raw, 12);
    await updateClientSecret(clientId, hash);
    return { client_id: clientId, client_secret: raw };
  }

  async setScopes(clientId: string, scopes: string[]) {
    await updateClientScopes(clientId, scopes);
  }

  async enable(clientId: string, enabled: boolean) {
    await updateClientEnabled(clientId, enabled);
  }
}

async function findClientById(clientId: string) {
  return this.clientRepo.findOne({ where: { clientId } });
}
async function updateClientSecret(clientId: string, newHash: string) {
  await this.clientRepo.update({ clientId }, { clientSecretHash: newHash });
}
async function updateClientScopes(clientId: string, newScopes: string[]) {
  await this.clientRepo.update({ clientId }, { scopes: newScopes });
}
async function updateClientEnabled(clientId: string, enabled: boolean) {
  await this.clientRepo.update({ clientId }, { enabled });
}
function cryptoRandom(len: number) {
  return [...crypto.getRandomValues(new Uint8Array(len))]
    .map(b => ('0' + (b & 0xff).toString(16)).slice(-2))
    .join('');
}