import { signPartnerToken } from '../utils/jwt';
import { schemas } from '../../common/validator';
import { errors } from '../../common/errors';
import { logger } from '../../common/logger';
import { db } from '../../modules/db';

type Role = 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';

export async function clientCredentials(input: unknown, role: Role) {
  const { client_id, client_secret, grant_type, scope } = schemas.partnerToken.parse(input);
  if (grant_type !== 'client_credentials') throw errors.BadRequest('Unsupported grant_type');

  const record = await db.clients.findById(client_id);
  if (!record || !record.enabled) throw errors.Unauthorized('Invalid client');

  const secretOk = await db.clients.verifySecret(client_id, client_secret);
  if (!secretOk) throw errors.Unauthorized('Invalid secret');

  if (record.role !== role) throw errors.Forbidden('Role mismatch');

  const requestedScopes = (scope || '').split(' ').filter(Boolean);
  const allowedScopes = record.scopes || [];
  const finalScopes = requestedScopes.length ? requestedScopes.filter(s => allowedScopes.includes(s)) : allowedScopes;

  const token = signPartnerToken({
    sub: record.id,
    role,
    clientId: record.partnerId,
    scopes: finalScopes,
    division: record.division || undefined,
  });

  logger.info(`Client token issued: ${client_id} role=${role} scopes=${finalScopes.join(',')}`);
  return { access_token: token, token_type: 'Bearer', expires_in: 600, scope: finalScopes.join(' ') };
}